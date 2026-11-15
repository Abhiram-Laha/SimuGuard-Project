"""Digital Twin hybrid network and cloud infrastructure graph engine.

Loads topology_graph.json, validates nodes and edges using Pydantic,
enriches implicit infrastructure relationships, and maintains a NetworkX directed graph.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
import networkx as nx
from pydantic import BaseModel, ConfigDict, Field
from simuguard.models.enums import AssetCriticality


class TopologyMetadata(BaseModel):
    """Metadata describing the target enterprise network estate."""

    model_config = ConfigDict(extra="ignore")

    organization: str = Field(..., description="Organization or infrastructure name")
    firewall_vendor: str = Field(..., description="Firewall vendor and PAN-OS version")
    perimeter_firewall: str = Field(..., description="Node ID of the primary perimeter firewall")
    compliance_frameworks: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks enforced across the estate",
    )


class TopologyNode(BaseModel):
    """A discrete node (firewall, network zone, compute cluster, IAM role, or storage bucket)."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Unique node identifier")
    name: str = Field(..., description="Display name of the asset")
    type: str = Field(..., description="Asset type classification (e.g. NGFW_Palo_Alto, Network_Zone)")
    criticality: AssetCriticality = Field(
        default=AssetCriticality.HIGH,
        description="Asset business criticality level",
    )
    zones: Optional[List[str]] = Field(default=None, description="Security zones associated with this device")
    threat_prevention_profile: Optional[str] = Field(default=None, description="Active NGFW threat profile")
    attached_workloads: Optional[List[str]] = Field(default=None, description="Workload IDs attached to this zone")
    attached_iam_role: Optional[str] = Field(default=None, description="IAM role attached to this compute resource")
    current_policies: Optional[List[str]] = Field(default=None, description="Existing IAM policies attached to role")
    data_classification: Optional[str] = Field(default=None, description="Data sensitivity classification")
    compliance_controls: Optional[List[str]] = Field(default=None, description="Compliance controls mapped to node")
    contains: Optional[List[str]] = Field(default=None, description="Entities contained in this network zone")
    security_groups: Optional[List[str]] = Field(default=None, description="Security group IDs associated with node")


class TopologyEdge(BaseModel):
    """A directed edge representing a security policy, network route, or IAM access path."""

    model_config = ConfigDict(extra="ignore")

    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    relationship: str = Field(..., description="Relationship type (e.g. ENFORCES_ZONE_POLICY, CROSS_ZONE_IAM_PATH)")
    blast_condition: Optional[str] = Field(
        default=None,
        description="Conditions under which risk or blast radius propagates across this edge",
    )


class DigitalTwinTopology(BaseModel):
    """Complete Digital Twin topology specification."""

    model_config = ConfigDict(extra="ignore")

    metadata: TopologyMetadata
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]


# Verified infrastructure security group associations for known workloads
DEFAULT_SG_WORKLOAD_MAPPINGS: Dict[str, str] = {
    "sg-analytics-web-01": "eks-analytics-worker-pool",
}


class DigitalTwinGraph:
    """NetworkX directed graph representation of the Digital Twin hybrid cloud estate."""

    def __init__(
        self,
        topology: Optional[DigitalTwinTopology] = None,
        sg_mappings: Optional[Dict[str, str]] = None,
    ):
        self._topology: Optional[DigitalTwinTopology] = topology
        self._graph: nx.DiGraph = nx.DiGraph()
        self._node_lookup: Dict[str, TopologyNode] = {}
        # Explicit security group to workload node mapping registry
        self._sg_mappings: Dict[str, str] = dict(DEFAULT_SG_WORKLOAD_MAPPINGS)
        if sg_mappings:
            self._sg_mappings.update(sg_mappings)

        if topology:
            self._build_graph(topology)

    @property
    def nx_graph(self) -> nx.DiGraph:
        """Access the underlying NetworkX directed graph."""
        return self._graph

    @property
    def topology(self) -> Optional[DigitalTwinTopology]:
        """Access the validated Pydantic topology data."""
        return self._topology

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    @classmethod
    def from_file(
        cls,
        path: Union[str, Path],
        sg_mappings: Optional[Dict[str, str]] = None,
    ) -> "DigitalTwinGraph":
        """Load and validate topology from a JSON file path."""
        file_path = Path(path).resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"Digital Twin topology file not found: {file_path}")

        raw_text = file_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
        validated_topology = DigitalTwinTopology.model_validate(data)
        return cls(topology=validated_topology, sg_mappings=sg_mappings)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        sg_mappings: Optional[Dict[str, str]] = None,
    ) -> "DigitalTwinGraph":
        """Load and validate topology from a dictionary."""
        validated_topology = DigitalTwinTopology.model_validate(data)
        return cls(topology=validated_topology, sg_mappings=sg_mappings)

    def register_security_group_mapping(self, sg_id: str, node_id: str) -> None:
        """Register an explicit mapping from a Security Group ID to a topology workload node."""
        self._sg_mappings[sg_id] = node_id

    def get_node_for_security_group(self, sg_id: str) -> Optional[TopologyNode]:
        """Resolve a Security Group ID to its associated topology node using explicit mappings.

        Never guesses or uses substring heuristics. Returns None if unmapped.
        """
        if not sg_id:
            return None

        # 1. Check explicit registry
        if sg_id in self._sg_mappings:
            target_node_id = self._sg_mappings[sg_id]
            return self.get_node(target_node_id)

        # 2. Check if any node explicitly declares this security group in its attributes
        for node in self._node_lookup.values():
            if node.security_groups and sg_id in node.security_groups:
                return node

        return None

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        """Retrieve a node by its unique identifier."""
        return self._node_lookup.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> List[TopologyNode]:
        """Retrieve all nodes matching a specific type."""
        return [n for n in self._node_lookup.values() if n.type == node_type]

    def get_nodes_by_zone(self, zone_name: str) -> List[TopologyNode]:
        """Retrieve firewall or zone nodes associated with a given zone name."""
        matches: List[TopologyNode] = []
        for n in self._node_lookup.values():
            if n.zones and zone_name in n.zones:
                matches.append(n)
            elif zone_name.lower() in n.name.lower() or zone_name.lower() in n.id.lower():
                matches.append(n)
        return matches

    def get_perimeter_firewall(self) -> Optional[TopologyNode]:
        """Get the primary perimeter firewall node specified in metadata."""
        if self._topology:
            fw_id = self._topology.metadata.perimeter_firewall
            return self.get_node(fw_id)
        return None

    def find_node_by_identifier(self, identifier: str) -> Optional[TopologyNode]:
        """Find a node by exact ID, exact name, or explicit attached attributes."""
        if not identifier:
            return None

        # Exact ID match
        if identifier in self._node_lookup:
            return self._node_lookup[identifier]

        cleaned = identifier.strip().lower()

        # Check name
        for node in self._node_lookup.values():
            if node.name.lower() == cleaned:
                return node

        # Check attached workloads or IAM roles
        for node in self._node_lookup.values():
            if node.attached_iam_role and node.attached_iam_role.lower() == cleaned:
                return node
            if node.attached_workloads and any(w.lower() == cleaned for w in node.attached_workloads):
                return node

        return None

    def _build_graph(self, topology: DigitalTwinTopology) -> None:
        """Construct the NetworkX DiGraph and enrich implicit relationships."""
        self._graph.clear()
        self._node_lookup.clear()

        # 1. Add all validated nodes
        for node in topology.nodes:
            self._node_lookup[node.id] = node
            self._graph.add_node(
                node.id,
                name=node.name,
                type=node.type,
                criticality=node.criticality.value,
                data=node,
            )

        # 2. Add all explicit edges from topology JSON
        for edge in topology.edges:
            # Handle invalid edges where source or target does not exist gracefully
            if edge.source not in self._node_lookup or edge.target not in self._node_lookup:
                continue

            self._graph.add_edge(
                edge.source,
                edge.target,
                relationship=edge.relationship,
                blast_condition=edge.blast_condition,
                is_enriched=False,
            )

        # 3. Enrich implicit relationships (Task 5):
        # A. Network Zone -> Compute Cluster (attached_workloads)
        # B. Compute Cluster -> IAM Role (attached_iam_role)
        for node in topology.nodes:
            # Enrich: Trust-DMZ -> EKS analytics worker pool
            if node.attached_workloads:
                for workload_id in node.attached_workloads:
                    if workload_id in self._node_lookup:
                        if not self._graph.has_edge(node.id, workload_id):
                            self._graph.add_edge(
                                node.id,
                                workload_id,
                                relationship="CONTAINS_WORKLOAD",
                                blast_condition=(
                                    f"Workload '{workload_id}' is located in network zone '{node.id}' "
                                    f"and inherits zone security boundaries and egress controls."
                                ),
                                is_enriched=True,
                            )

            # Enrich: EKS analytics worker pool -> analytics IAM role
            if node.attached_iam_role:
                role_id = node.attached_iam_role
                if role_id in self._node_lookup:
                    if not self._graph.has_edge(node.id, role_id):
                        self._graph.add_edge(
                            node.id,
                            role_id,
                            relationship="ASSUMES_ROLE",
                            blast_condition=(
                                f"Workload '{node.id}' assumes IAM role '{role_id}' for AWS "
                                f"cloud service access."
                            ),
                            is_enriched=True,
                        )
