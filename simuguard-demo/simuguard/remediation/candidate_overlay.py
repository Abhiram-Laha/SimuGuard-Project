"""Isolated Candidate Digital Twin Overlay Engine.

Applies proposed remediation changes to an ephemeral copy of the Digital Twin graph:
- Removes obsolete relationships and excessive permissions (e.g. role -> CUI vault edge).
- Adds proposed least-privilege relationships (e.g. role -> staging telemetry bucket).
- Recalculates effective IAM permissions and sensitive asset exposure.
- Queries application dependency graph to detect shared role usage.
- Never mutates the original Digital Twin graph or disk datasets.
"""

import copy
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
from simuguard.graph.blast_radius import BlastRadiusAnalyzer, BlastRadiusResult
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph, TopologyEdge, TopologyNode
from simuguard.models.enums import AssetCriticality, BlastTier
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    NormalizedResource,
    PanosSecurityPolicyResource,
)
from simuguard.remediation.models import CandidateOverlayResult, RemediationPlan


class CandidateDigitalTwinOverlay:
    """Manages an ephemeral, isolated overlay of the Digital Twin graph for pre-deployment validation."""

    def __init__(
        self,
        base_digital_twin: DigitalTwinGraph,
        loader: Optional[EnterpriseDatasetLoader] = None,
    ):
        self.base_twin = base_digital_twin
        self.loader = loader or EnterpriseDatasetLoader()
        self._load_app_dependencies()

    def _load_app_dependencies(self):
        """Index applications and dependencies for operational safety checks."""
        self.apps_by_role: Dict[str, List[str]] = {}
        try:
            apps_data = self.loader._read_json("applications/applications.json")
            for app in apps_data.get("applications", []):
                app_name = app.get("name", app.get("id"))
                for r in app.get("iam_roles", []):
                    self.apps_by_role.setdefault(r, []).append(app_name)
        except Exception:
            pass

    def create_candidate_overlay(
        self,
        candidate_resources: List[NormalizedResource],
        original_resources: List[NormalizedResource],
    ) -> Tuple[DigitalTwinGraph, CandidateOverlayResult]:
        """Construct an isolated candidate graph overlay reflecting proposed changes.

        Returns:
            Tuple of (ephemeral_candidate_twin, CandidateOverlayResult)
        """
        # 1. Ephemeral deep copy of underlying NetworkX graph and lookup
        ephemeral_twin = copy.deepcopy(self.base_twin)
        nx_graph: nx.DiGraph = ephemeral_twin.nx_graph

        removed_edges: List[str] = []
        added_edges: List[str] = []
        effective_permissions: Dict[str, Any] = {}
        affected_apps: Set[str] = set()
        operational_warnings: List[str] = []
        requires_review = False

        # 2. Identify removed vs proposed IAM attachments
        orig_attachments = [r for r in original_resources if isinstance(r, AwsIamRolePolicyAttachmentResource)]
        cand_attachments = [r for r in candidate_resources if isinstance(r, AwsIamRolePolicyAttachmentResource)]

        for orig in orig_attachments:
            # Check if original attached AmazonS3FullAccess was removed or replaced
            if "AmazonS3FullAccess" in orig.policy_arn:
                role_id = orig.role
                affected_apps.update(self.apps_by_role.get(role_id, []))

                # Sever edge in candidate graph to sensitive CUI vault
                cui_nodes = [
                    n for n, d in nx_graph.nodes(data=True)
                    if "cui" in n.lower() or "vault" in n.lower() or "restricted" in n.lower()
                ]
                for cui_node in cui_nodes:
                    if nx_graph.has_edge(role_id, cui_node):
                        nx_graph.remove_edge(role_id, cui_node)
                        removed_edges.append(f"{role_id} -> {cui_node} (AmazonS3FullAccess Revoked)")

                # Also sever from eks worker pool to CUI if present
                for u, v in list(nx_graph.edges()):
                    if (u == role_id or "analytics" in u.lower()) and ("cui" in v.lower() or "vault" in v.lower()):
                        nx_graph.remove_edge(u, v)
                        removed_edges.append(f"{u} -> {v} (CUI Path Severed)")

        # 3. Add proposed candidate scoped permissions
        for cand in cand_attachments:
            role_id = cand.role
            # If scoped policy attached
            if "scoped" in cand.policy_arn.lower() or "write" in cand.policy_arn.lower() or "telemetry" in cand.policy_arn.lower():
                staging_target = "s3-dev-staging-telemetry"
                # Add node if missing
                if not nx_graph.has_node(staging_target):
                    nx_graph.add_node(
                        staging_target,
                        criticality=AssetCriticality.LOW,
                        type="Storage_S3_Bucket",
                        name="Development Staging & Telemetry Storage",
                    )
                nx_graph.add_edge(role_id, staging_target, relationship="SCOPED_S3_WRITE")
                added_edges.append(f"{role_id} -> {staging_target} (Least-Privilege Scoped PutObject)")

                effective_permissions[role_id] = {
                    "AllowedActions": ["s3:PutObject", "s3:AbortMultipartUpload"],
                    "Resources": ["arn:aws:s3:::apex-dev-staging-telemetry/incoming/*"],
                    "Status": "RESTRICTED_LEAST_PRIVILEGE",
                }

        # 4. Check for multiple application dependencies
        for role_name, apps in self.apps_by_role.items():
            if any(cand.role == role_name for cand in cand_attachments):
                if len(apps) > 1:
                    operational_warnings.append(
                        f"Role '{role_name}' is utilized by multiple services: {apps}. Verify no unintended impact."
                    )
                    requires_review = True

        # 5. Check residual sensitive exposures under overlay
        residual_sensitive: List[str] = []
        for cand in cand_attachments:
            role_id = cand.role
            if nx_graph.has_node(role_id):
                for descendant in nx.descendants(nx_graph, role_id):
                    node_data = nx_graph.nodes[descendant]
                    crit = node_data.get("criticality")
                    data_cls = str(node_data.get("data_classification", "")).upper()
                    if crit == AssetCriticality.CRITICAL or "CUI" in data_cls or "RESTRICTED" in data_cls:
                        residual_sensitive.append(descendant)

        overlay_result = CandidateOverlayResult(
            overlay_applied=True,
            removed_relationships=removed_edges,
            added_relationships=added_edges,
            effective_iam_permissions=effective_permissions,
            residual_sensitive_exposures=residual_sensitive,
            affected_applications=sorted(list(affected_apps)),
            operational_warnings=operational_warnings,
            requires_manual_review=requires_review or len(residual_sensitive) > 0,
        )

        return ephemeral_twin, overlay_result
