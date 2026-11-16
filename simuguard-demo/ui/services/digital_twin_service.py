"""Digital Twin Graph Service — provides read-only graph topology access, search, filtering, and blast-radius extraction."""

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph, TopologyNode
from simuguard.models.enums import AssetCriticality

CATEGORY_MAPPINGS: Dict[str, str] = {
    "NGFW_Palo_Alto": "Firewalls & Perimeter",
    "Panorama_Server": "Firewalls & Perimeter",
    "Network_Zone": "Network Zones & Subnets",
    "Network_Subnet": "Network Zones & Subnets",
    "Cloud_Account": "Cloud Infrastructure",
    "Compute_Cluster": "Cloud Infrastructure",
    "Compute_Instance": "Cloud Infrastructure",
    "Load_Balancer_ALB": "Cloud Infrastructure",
    "KMS_Key": "Cloud Infrastructure",
    "Business_Application": "Business Applications",
    "Storage_S3_Bucket": "Data Assets & Storage",
    "Database_RDS_PostgreSQL": "Data Assets & Storage",
    "Data_Asset": "Data Assets & Storage",
    "IAM_Role": "Cloud IAM Roles",
    "SailPoint_Identity": "SailPoint Identity Governance",
    "SailPoint_Role": "SailPoint Identity Governance",
    "SailPoint_AccessProfile": "SailPoint Identity Governance",
    "SailPoint_Entitlement": "SailPoint Identity Governance",
    "SailPoint_Account": "SailPoint Identity Governance",
    "SailPoint_Source": "SailPoint Identity Governance",
    "SailPoint_IdentityProfile": "SailPoint Identity Governance",
    "SailPoint_Tenant": "SailPoint Identity Governance",
    "SailPoint_AccessRequest": "SailPoint Identity Governance",
    "SailPoint_Approval": "SailPoint Identity Governance",
    "SailPoint_ProvisioningEvent": "SailPoint Identity Governance",
    "SailPoint_Certification": "SailPoint Identity Governance",
}

CATEGORY_COLORS: Dict[str, str] = {
    "Firewalls & Perimeter": "#ef4444",      # Red
    "Network Zones & Subnets": "#3b82f6",    # Blue
    "Cloud Infrastructure": "#0284c7",       # Sky
    "Business Applications": "#6366f1",      # Indigo
    "Data Assets & Storage": "#10b981",      # Emerald Green
    "Cloud IAM Roles": "#f59e0b",            # Amber
    "SailPoint Identity Governance": "#8b5cf6", # Purple
}


class DigitalTwinService:
    """Service providing cached, read-only exploration of the Digital Twin."""

    _instance: Optional["DigitalTwinService"] = None

    def __init__(self, loader: Optional[EnterpriseDatasetLoader] = None):
        self.loader = loader or EnterpriseDatasetLoader()
        self._dt: Optional[DigitalTwinGraph] = None

    @classmethod
    def get_instance(cls) -> "DigitalTwinService":
        if cls._instance is None:
            cls._instance = DigitalTwinService()
        return cls._instance

    @property
    def dt(self) -> DigitalTwinGraph:
        """Lazily load and cache the Digital Twin graph."""
        if self._dt is None:
            self._dt = self.loader.load_as_digital_twin_graph()
        return self._dt

    def get_metrics(self) -> Dict[str, Any]:
        """Return summary metrics of the Digital Twin topology."""
        g = self.dt.nx_graph
        node_count = g.number_of_nodes()
        edge_count = g.number_of_edges()

        # Count by category
        cat_counts: Dict[str, int] = {}
        for node_id in g.nodes():
            node = self.dt._node_lookup.get(node_id)
            node_type = node.type if node else "Unknown"
            cat = CATEGORY_MAPPINGS.get(node_type, "Other")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        # Count sensitive assets
        sensitive_count = sum(
            1 for n in self.dt._node_lookup.values()
            if getattr(n, "data_classification", None) or n.type in ["Data_Asset", "Storage_S3_Bucket", "Database_RDS_PostgreSQL"]
        )

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "category_counts": cat_counts,
            "sensitive_assets_count": sensitive_count,
            "organization": self.dt.topology.metadata.organization if self.dt.topology else "Apex Global Technologies",
            "firewall_vendor": self.dt.topology.metadata.firewall_vendor if self.dt.topology else "Palo Alto Networks PAN-OS 11.1",
        }

    def search_nodes(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        domain: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search and filter topology nodes."""
        results: List[Dict[str, Any]] = []
        g = self.dt.nx_graph

        for node_id in g.nodes():
            node = self.dt._node_lookup.get(node_id)
            if not node:
                continue

            node_type = node.type
            cat = CATEGORY_MAPPINGS.get(node_type, "Other")

            # Category filter
            if category and category.upper() != "ALL" and cat != category:
                continue

            # Domain filter
            if domain and domain.upper() != "ALL":
                is_identity = cat == "SailPoint Identity Governance"
                if domain == "NETWORK_SECURITY" and is_identity:
                    continue
                if domain == "IDENTITY_GOVERNANCE" and not is_identity:
                    continue

            # Text query
            if query and query.strip():
                q = query.strip().lower()
                name_match = q in node.name.lower()
                id_match = q in node.id.lower()
                type_match = q in node.type.lower()
                if not (name_match or id_match or type_match):
                    continue

            results.append({
                "id": node.id,
                "name": node.name,
                "type": node.type,
                "category": cat,
                "criticality": node.criticality.value if hasattr(node.criticality, "value") else str(node.criticality),
                "color": CATEGORY_COLORS.get(cat, "#64748b"),
                "degree": g.degree(node_id),
            })

            if len(results) >= limit:
                break

        return results

    def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve comprehensive asset details, relationships, and connected neighbors."""
        node = self.dt._node_lookup.get(node_id)
        if not node:
            return None

        g = self.dt.nx_graph
        cat = CATEGORY_MAPPINGS.get(node.type, "Other")

        # Outgoing relationships
        outgoing = []
        if g.has_node(node_id):
            for _, target_id, edge_data in g.out_edges(node_id, data=True):
                target_node = self.dt._node_lookup.get(target_id)
                outgoing.append({
                    "target_id": target_id,
                    "target_name": target_node.name if target_node else target_id,
                    "target_type": target_node.type if target_node else "Unknown",
                    "relationship": edge_data.get("relationship", "CONNECTED_TO"),
                    "blast_condition": edge_data.get("blast_condition"),
                })

        # Incoming relationships
        incoming = []
        if g.has_node(node_id):
            for source_id, _, edge_data in g.in_edges(node_id, data=True):
                source_node = self.dt._node_lookup.get(source_id)
                incoming.append({
                    "source_id": source_id,
                    "source_name": source_node.name if source_node else source_id,
                    "source_type": source_node.type if source_node else "Unknown",
                    "relationship": edge_data.get("relationship", "CONNECTED_TO"),
                    "blast_condition": edge_data.get("blast_condition"),
                })

        # Metadata dictionary
        node_dict = node.model_dump(exclude_unset=True)
        raw_metadata = {k: v for k, v in node_dict.items() if k not in ["id", "name", "type", "criticality"]}

        return {
            "id": node.id,
            "name": node.name,
            "type": node.type,
            "category": cat,
            "color": CATEGORY_COLORS.get(cat, "#64748b"),
            "criticality": node.criticality.value if hasattr(node.criticality, "value") else str(node.criticality),
            "metadata": raw_metadata,
            "outgoing_edges": outgoing,
            "incoming_edges": incoming,
            "total_relationships": len(outgoing) + len(incoming),
        }

    def generate_topology_svg(
        self,
        center_node_id: Optional[str] = None,
        category_filter: Optional[str] = None,
        max_nodes: int = 50,
    ) -> str:
        """Generate a clean, scalable SVG representation of the topology subgraph."""
        g = self.dt.nx_graph
        subgraph_nodes = set()

        if center_node_id and g.has_node(center_node_id):
            subgraph_nodes.add(center_node_id)
            subgraph_nodes.update(g.neighbors(center_node_id))
            subgraph_nodes.update(g.predecessors(center_node_id))
        else:
            # Filter nodes by category or take highest degree nodes
            for n in g.nodes():
                node_obj = self.dt._node_lookup.get(n)
                if not node_obj:
                    continue
                if category_filter and category_filter != "ALL":
                    if CATEGORY_MAPPINGS.get(node_obj.type) != category_filter:
                        continue
                subgraph_nodes.add(n)
                if len(subgraph_nodes) >= max_nodes:
                    break

        if not subgraph_nodes:
            subgraph_nodes = set(list(g.nodes())[:max_nodes])

        subgraph = g.subgraph(subgraph_nodes)
        pos = nx.spring_layout(subgraph, seed=42, k=1.8, iterations=50)

        # SVG canvas dimensions
        width = 860
        height = 480
        padding = 50

        # Scale coordinates
        xs = [p[0] for p in pos.values()] or [0]
        ys = [p[1] for p in pos.values()] or [0]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = (max_x - min_x) or 1.0
        span_y = (max_y - min_y) or 1.0

        coords = {}
        for n, (x, y) in pos.items():
            cx = padding + ((x - min_x) / span_x) * (width - 2 * padding)
            cy = padding + ((y - min_y) / span_y) * (height - 2 * padding)
            coords[n] = (cx, cy)

        # Build SVG elements
        svg_lines = [
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" style="background:#ffffff; border:1px solid #e2e8f0; border-radius:8px;">',
            '<defs>',
            '  <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '    <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />',
            '  </marker>',
            '</defs>',
        ]

        # Draw Edges
        for u, v, data in subgraph.edges(data=True):
            if u in coords and v in coords:
                x1, y1 = coords[u]
                x2, y2 = coords[v]
                rel = data.get("relationship", "")
                svg_lines.append(
                    f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="#cbd5e1" stroke-width="1.5" marker-end="url(#arrow)">'
                    f'<title>{html.escape(rel)}</title></line>'
                )

        # Draw Nodes
        for n in subgraph.nodes():
            if n in coords:
                cx, cy = coords[n]
                node_obj = self.dt._node_lookup.get(n)
                node_type = node_obj.type if node_obj else ""
                cat = CATEGORY_MAPPINGS.get(node_type, "Other")
                color = CATEGORY_COLORS.get(cat, "#64748b")
                is_selected = n == center_node_id

                stroke = "#0f172a" if is_selected else "#ffffff"
                stroke_width = 3 if is_selected else 1.5
                r = 14 if is_selected else 9

                label = (node_obj.name if node_obj else n)[:18]

                svg_lines.append(
                    f'<g id="node_{n}">'
                    f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{color}" stroke="{stroke}" stroke-width="{stroke_width}">'
                    f'<title>{html.escape(node_obj.name if node_obj else n)} ({node_type})</title></circle>'
                    f'<text x="{cx:.1f}" y="{cy + r + 11:.1f}" font-size="9" font-family="sans-serif" font-weight="500" fill="#334155" text-anchor="middle">{html.escape(label)}</text>'
                    f'</g>'
                )

        svg_lines.append('</svg>')
        return "\n".join(svg_lines)
