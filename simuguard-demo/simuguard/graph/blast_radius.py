"""Blast Radius Traversal Engine for SimuGuard AI.

Maps parsed Terraform resources to Digital Twin topology nodes, evaluates
edge-level blast conditions, and classifies impacts into AFFECTED, NOT_AFFECTED,
and UNKNOWN statuses.
"""

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field
from simuguard.graph.digital_twin import DigitalTwinGraph, TopologyNode
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import AssetCriticality, BlastTier, ImpactStatus
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    NormalizedResource,
    PanosSecurityPolicyResource,
)


class BlastPathStep(BaseModel):
    """A single step along a blast radius propagation path."""

    model_config = ConfigDict(extra="ignore")

    from_node: str = Field(..., description="Source node ID")
    to_node: str = Field(..., description="Target node ID")
    relationship: str = Field(..., description="Edge relationship type")
    condition_evaluated: Optional[str] = Field(default=None, description="Blast condition evaluated")
    condition_met: bool = Field(default=True, description="Whether the condition was satisfied")


class ImpactedNode(BaseModel):
    """An infrastructure node within the calculated blast radius."""

    model_config = ConfigDict(extra="ignore")

    node_id: str = Field(..., description="Unique node identifier matching topology")
    node_name: str = Field(..., description="Display name of the asset")
    node_type: str = Field(..., description="Asset type classification")
    criticality: AssetCriticality = Field(..., description="Business criticality level")
    status: ImpactStatus = Field(default=ImpactStatus.AFFECTED, description="Explicit impact status")
    tier: BlastTier = Field(..., description="DIRECT or CASCADING blast tier")
    impact_reason: str = Field(..., description="Specific explanation of why this node is affected")
    path_from_trigger: List[str] = Field(
        default_factory=list,
        description="Sequence of node IDs traversed from the trigger resource",
    )
    relationships_traversed: List[str] = Field(
        default_factory=list,
        description="Edge relationships traversed to reach this node",
    )
    trigger_resource: str = Field(..., description="Terraform resource identifier that caused this impact")

    def to_affected_asset(self) -> AffectedAsset:
        """Convert this impacted node into a standardized AffectedAsset model."""
        return AffectedAsset(
            asset_id=self.node_id,
            asset_name=self.node_name,
            asset_type=self.node_type,
            criticality=self.criticality,
            blast_tier=self.tier,
            impact_description=self.impact_reason,
        )


class UnknownImpactAsset(BaseModel):
    """Represents an unmapped resource or an asset whose impact cannot be determined."""

    model_config = ConfigDict(extra="ignore")

    resource_identifier: str = Field(..., description="Identifier of the resource or node")
    resource_type: str = Field(..., description="Type of resource (e.g. aws_security_group_rule)")
    reason: str = Field(..., description="Explanation of why the impact status is UNKNOWN")
    status: ImpactStatus = Field(default=ImpactStatus.UNKNOWN, description="Always UNKNOWN")


class BlastRadiusResult(BaseModel):
    """Comprehensive result of a blast radius analysis distinguishing impact statuses."""

    model_config = ConfigDict(extra="ignore")

    evaluated_resources: List[str] = Field(
        default_factory=list,
        description="List of Terraform resources evaluated",
    )
    direct_impacts: List[ImpactedNode] = Field(
        default_factory=list,
        description="Directly modified or targeted infrastructure nodes (AFFECTED)",
    )
    cascading_impacts: List[ImpactedNode] = Field(
        default_factory=list,
        description="Downstream or transitively impacted infrastructure nodes (AFFECTED)",
    )
    not_affected_nodes: List[str] = Field(
        default_factory=list,
        description="Nodes in the topology verified to be NOT_AFFECTED based on complete mapping",
    )
    unknown_nodes: List[str] = Field(
        default_factory=list,
        description="Topology nodes whose status is UNKNOWN due to unmapped resources or missing topology data",
    )
    unknown_impacts: List[UnknownImpactAsset] = Field(
        default_factory=list,
        description="Detailed records for resources or nodes with UNKNOWN status",
    )
    unmapped_resources: List[str] = Field(
        default_factory=list,
        description="Warning list of Terraform resources that could not be mapped to topology",
    )

    @property
    def all_affected_nodes(self) -> List[ImpactedNode]:
        """Return combined list of direct and cascading impacted nodes."""
        return self.direct_impacts + self.cascading_impacts

    @property
    def total_affected_count(self) -> int:
        return len(self.all_affected_nodes)

    @property
    def unreachable_nodes(self) -> List[str]:
        """Backward-compatibility property returning not_affected_nodes (or unknown_nodes when unmapped)."""
        if self.not_affected_nodes:
            return self.not_affected_nodes
        return self.unknown_nodes

    def to_affected_assets(self) -> List[AffectedAsset]:
        """Convert all impacted nodes to standardized AffectedAsset instances."""
        return [node.to_affected_asset() for node in self.all_affected_nodes]


class BlastRadiusAnalyzer:
    """Evaluates blast radius propagation across the Digital Twin topology."""

    def __init__(self, digital_twin: DigitalTwinGraph):
        self.dt = digital_twin
        self.graph = digital_twin.nx_graph

    def analyze_resources(self, resources: List[NormalizedResource]) -> BlastRadiusResult:
        """Analyze the collective blast radius for a list of normalized Terraform resources."""
        result = BlastRadiusResult()
        impacted_by_id: Dict[str, ImpactedNode] = {}
        evaluated_res_labels: List[str] = []
        has_unmapped_resource = False

        for res in resources:
            res_label = f"{res.resource_type}.{res.resource_name}"
            evaluated_res_labels.append(res_label)

            if isinstance(res, PanosSecurityPolicyResource):
                self._evaluate_panos_policy(res, impacted_by_id, result)

            elif isinstance(res, AwsSecurityGroupRuleResource):
                was_mapped = self._evaluate_aws_security_group_rule(res, impacted_by_id, result)
                if not was_mapped:
                    has_unmapped_resource = True

            elif isinstance(res, AwsIamRolePolicyAttachmentResource):
                was_mapped = self._evaluate_aws_iam_attachment(res, impacted_by_id, result)
                if not was_mapped:
                    has_unmapped_resource = True

            else:
                has_unmapped_resource = True
                warning = f"{res_label} (Resource type not mapped to topology)"
                result.unmapped_resources.append(warning)
                result.unknown_impacts.append(
                    UnknownImpactAsset(
                        resource_identifier=res_label,
                        resource_type=res.resource_type,
                        reason="Resource type has no defined mapping handler in Digital Twin engine.",
                    )
                )

        result.evaluated_resources = evaluated_res_labels

        # Partition into direct and cascading impacts
        for node in impacted_by_id.values():
            if node.tier == BlastTier.DIRECT:
                result.direct_impacts.append(node)
            else:
                result.cascading_impacts.append(node)

        # Classify remaining topology nodes
        all_topology_nodes = set(self.graph.nodes())
        affected_ids = set(impacted_by_id.keys())
        remaining_node_ids = sorted(list(all_topology_nodes - affected_ids))

        # Rule 2: If there are unmapped resources in the change set, missing topology data
        # cannot be treated as proof of isolation. Do NOT classify assets as confirmed safe.
        if has_unmapped_resource:
            result.unknown_nodes = remaining_node_ids
            result.not_affected_nodes = []
            for nid in remaining_node_ids:
                result.unknown_impacts.append(
                    UnknownImpactAsset(
                        resource_identifier=nid,
                        resource_type="Topology_Node",
                        reason=(
                            f"Asset '{nid}' cannot be confirmed NOT_AFFECTED because change set contains "
                            f"unmapped resources ({', '.join(result.unmapped_resources)}). Missing topology "
                            f"relationships do not guarantee isolation."
                        ),
                    )
                )
        else:
            # When all resources are fully mapped, remaining nodes are confirmed NOT_AFFECTED
            result.not_affected_nodes = remaining_node_ids
            result.unknown_nodes = []

        return result

    def _evaluate_panos_policy(
        self,
        res: PanosSecurityPolicyResource,
        impacted: Dict[str, ImpactedNode],
        result: BlastRadiusResult,
    ) -> None:
        """Evaluate blast propagation from a Palo Alto firewall security policy."""
        res_label = f"{res.resource_type}.{res.resource_name}"
        fw_node = self.dt.get_perimeter_firewall()

        if not fw_node:
            result.unmapped_resources.append(f"{res_label} (No perimeter firewall found in topology)")
            result.unknown_impacts.append(
                UnknownImpactAsset(
                    resource_identifier=res_label,
                    resource_type="panos_security_policy",
                    reason="Perimeter firewall specified in topology metadata does not exist in graph.",
                )
            )
            return

        # 1. Direct Impact: Perimeter Firewall
        rule_names = [r.name for r in res.rules]
        rules_desc = ", ".join(f"'{name}'" for name in rule_names)
        self._record_impact(
            impacted=impacted,
            node=fw_node,
            tier=BlastTier.DIRECT,
            reason=f"Security policy containing rule(s) {rules_desc} deployed directly onto perimeter firewall",
            path=[fw_node.id],
            relationships=["DIRECT_CONFIG"],
            trigger=res_label,
        )

        for rule in res.rules:
            is_app_id_bypass = any(app.lower() == "any" for app in rule.applications)
            is_dest_wildcard = any(addr.lower() == "any" for addr in rule.destination_addresses)
            is_threat_disabled = (
                rule.security_profile_group is not None
                and rule.security_profile_group.lower() == "none"
            )

            # 2. Check source zones (e.g. Trust-DMZ)
            for sz in rule.source_zones:
                zone_nodes = self.dt.get_nodes_by_zone(sz)
                for zn in zone_nodes:
                    if zn.id == fw_node.id:
                        continue

                    edge_data = self.graph.get_edge_data(fw_node.id, zn.id) or {}
                    rel = edge_data.get("relationship", "ENFORCES_ZONE_POLICY")
                    blast_condition = edge_data.get("blast_condition", "")

                    reason = f"Security rule '{rule.name}' modifies egress filtering for zone '{sz}'"
                    if is_app_id_bypass and is_dest_wildcard:
                        reason += (
                            " (App-ID disabled with destination 'any', potentially permitting "
                            "uninspected egress tunneling)"
                        )

                    # Zone itself is directly affected by the policy update
                    self._record_impact(
                        impacted=impacted,
                        node=zn,
                        tier=BlastTier.DIRECT,
                        reason=reason,
                        path=[fw_node.id, zn.id],
                        relationships=[rel],
                        trigger=res_label,
                    )

                    # 3. Conditional Traversal: Workloads inside this zone
                    # Condition: Traversal to workloads propagates uninspected egress risk
                    # ONLY if the rule bypasses App-ID or destination filtering
                    if is_app_id_bypass or is_dest_wildcard:
                        if self.graph.has_node(zn.id):
                            for neighbor in self.graph.successors(zn.id):
                                n_edge = self.graph.get_edge_data(zn.id, neighbor) or {}
                                n_rel = n_edge.get("relationship")

                                # Case A: Zone directly contains workload (Phase 3 model)
                                if n_rel == "CONTAINS_WORKLOAD":
                                    workload_node = self.dt.get_node(neighbor)
                                    if workload_node:
                                        w_reason = (
                                            f"Workload hosted in zone '{zn.id}' is potentially exposed: inherits "
                                            f"uninspected outbound egress pathway under rule '{rule.name}'"
                                        )
                                        w_path = [fw_node.id, zn.id, neighbor]
                                        w_rels = [rel, "CONTAINS_WORKLOAD"]
                                        self._record_impact(
                                            impacted=impacted,
                                            node=workload_node,
                                            tier=BlastTier.CASCADING,
                                            reason=w_reason,
                                            path=w_path,
                                            relationships=w_rels,
                                            trigger=res_label,
                                        )
                                        self._propagate_workload_impact(
                                            workload_node, w_path, w_rels, res_label, impacted
                                        )

                                # Case B: Zone contains subnet which contains workload (Enterprise model)
                                elif n_rel == "CONTAINS_SUBNET":
                                    subnet_node = self.dt.get_node(neighbor)
                                    if subnet_node:
                                        s_path = [fw_node.id, zn.id, neighbor]
                                        s_rels = [rel, "CONTAINS_SUBNET"]
                                        self._record_impact(
                                            impacted=impacted,
                                            node=subnet_node,
                                            tier=BlastTier.CASCADING,
                                            reason=(
                                                f"Subnet '{subnet_node.id}' in zone '{zn.id}' inherits uninspected "
                                                f"outbound egress pathway under rule '{rule.name}'"
                                            ),
                                            path=s_path,
                                            relationships=s_rels,
                                            trigger=res_label,
                                        )
                                        for s_succ in self.graph.successors(subnet_node.id):
                                            s_edge = self.graph.get_edge_data(subnet_node.id, s_succ) or {}
                                            if s_edge.get("relationship") == "CONTAINS_WORKLOAD":
                                                sw_node = self.dt.get_node(s_succ)
                                                if sw_node:
                                                    sw_path = s_path + [s_succ]
                                                    sw_rels = s_rels + ["CONTAINS_WORKLOAD"]
                                                    self._record_impact(
                                                        impacted=impacted,
                                                        node=sw_node,
                                                        tier=BlastTier.CASCADING,
                                                        reason=(
                                                            f"Workload hosted in subnet '{subnet_node.id}' (zone '{zn.id}') "
                                                            f"is potentially exposed: inherits uninspected outbound egress "
                                                            f"pathway under rule '{rule.name}'"
                                                        ),
                                                        path=sw_path,
                                                        relationships=sw_rels,
                                                        trigger=res_label,
                                                    )
                                                    self._propagate_workload_impact(
                                                        sw_node, sw_path, sw_rels, res_label, impacted
                                                    )

            # 4. Conditional Traversal: Inter-zone routing if threat profiles are disabled
            # Blast condition: "Removing Security Profile Groups exposes inter-zone traffic..."
            if is_threat_disabled:
                for neighbor in self.graph.successors(fw_node.id):
                    edge_data = self.graph.get_edge_data(fw_node.id, neighbor) or {}
                    if edge_data.get("relationship") == "ZONE_INTERCONNECT_ROUTING":
                        rz_node = self.dt.get_node(neighbor)
                        if rz_node:
                            self._record_impact(
                                impacted=impacted,
                                node=rz_node,
                                tier=BlastTier.CASCADING,
                                reason=(
                                    f"Disabling Security Profile Groups (threat inspection = 'none') on rule "
                                    f"'{rule.name}' satisfies ZONE_INTERCONNECT_ROUTING blast condition: "
                                    f"potentially exposes inter-zone routing to uninspected malware payloads "
                                    f"and lateral movement"
                                ),
                                path=[fw_node.id, neighbor],
                                relationships=["ZONE_INTERCONNECT_ROUTING"],
                                trigger=res_label,
                            )

    def _evaluate_aws_security_group_rule(
        self,
        res: AwsSecurityGroupRuleResource,
        impacted: Dict[str, ImpactedNode],
        result: BlastRadiusResult,
    ) -> bool:
        """Evaluate blast propagation from an AWS security group rule.

        Returns True if mapped to an explicit workload, False if unmapped.
        """
        res_label = f"{res.resource_type}.{res.resource_name}"
        sg_id = res.security_group_id or ""

        # Explicit mapping lookup (No substring guessing)
        mapped_workload = self.dt.get_node_for_security_group(sg_id)

        if not mapped_workload:
            warning = f"{res_label} (Security group '{sg_id}' has no verified mapping in Digital Twin)"
            result.unmapped_resources.append(warning)
            result.unknown_impacts.append(
                UnknownImpactAsset(
                    resource_identifier=res_label,
                    resource_type="aws_security_group_rule",
                    reason=(
                        f"Security group '{sg_id}' is absent from Digital Twin topology mappings. "
                        f"True workload associations cannot be determined without explicit topology data."
                    ),
                )
            )
            return False

        is_wide_egress = any(c == "0.0.0.0/0" for c in res.cidr_blocks)
        reason = f"Explicitly mapped security group '{sg_id}' on workload '{mapped_workload.id}' updated"
        if is_wide_egress:
            reason += " with unrestricted 0.0.0.0/0 outbound egress"

        # Direct impact on compute workload
        w_path = [mapped_workload.id]
        w_rels = ["APPLIES_SECURITY_GROUP"]
        self._record_impact(
            impacted=impacted,
            node=mapped_workload,
            tier=BlastTier.DIRECT,
            reason=reason,
            path=w_path,
            relationships=w_rels,
            trigger=res_label,
        )
        self._propagate_workload_impact(
            mapped_workload, w_path, w_rels, res_label, impacted
        )

        # Cascading: Identify the parent network zone containing this workload
        for parent in self.graph.predecessors(mapped_workload.id):
            edge_data = self.graph.get_edge_data(parent, mapped_workload.id) or {}
            if edge_data.get("relationship") == "CONTAINS_WORKLOAD":
                parent_node = self.dt.get_node(parent)
                if parent_node:
                    self._record_impact(
                        impacted=impacted,
                        node=parent_node,
                        tier=BlastTier.CASCADING,
                        reason=(
                            f"Zone boundary potentially weakened by unrestricted egress rule on hosted "
                            f"workload '{mapped_workload.id}'"
                        ),
                        path=[mapped_workload.id, parent],
                        relationships=["WORKLOAD_IN_ZONE"],
                        trigger=res_label,
                    )
        return True

    def _evaluate_aws_iam_attachment(
        self,
        res: AwsIamRolePolicyAttachmentResource,
        impacted: Dict[str, ImpactedNode],
        result: BlastRadiusResult,
    ) -> bool:
        """Evaluate blast propagation from an AWS IAM role policy attachment.

        Returns True if mapped to an existing role, False if unmapped.
        """
        res_label = f"{res.resource_type}.{res.resource_name}"
        role_node = self.dt.get_node(res.role) or self.dt.find_node_by_identifier(res.role)

        if not role_node:
            warning = f"{res_label} (IAM role '{res.role}' not found in Digital Twin)"
            result.unmapped_resources.append(warning)
            result.unknown_impacts.append(
                UnknownImpactAsset(
                    resource_identifier=res_label,
                    resource_type="aws_iam_role_policy_attachment",
                    reason=f"IAM role '{res.role}' is not present in Digital Twin topology.",
                )
            )
            return False

        is_admin_or_s3_full = "s3fullaccess" in res.policy_arn.lower() or "admin" in res.policy_arn.lower()

        # 1. Direct Impact: IAM Role
        self._record_impact(
            impacted=impacted,
            node=role_node,
            tier=BlastTier.DIRECT,
            reason=f"Policy '{res.policy_arn.split('/')[-1]}' attached to IAM role '{role_node.id}'",
            path=[role_node.id],
            relationships=["ATTACH_POLICY"],
            trigger=res_label,
        )

        # 2. Conditional Traversal: Downstream sensitive targets (CROSS_ZONE_IAM_PATH, ACCESSES_DATA_STORE, CAN_ACCESS)
        # Condition: "Granting AmazonS3FullAccess gives pods in Trust-DMZ unrestricted read and write privileges..."
        # Only propagates if the policy grants broad S3 or admin permissions
        if is_admin_or_s3_full:
            if self.graph.has_node(role_node.id):
                for neighbor in self.graph.successors(role_node.id):
                    edge_data = self.graph.get_edge_data(role_node.id, neighbor) or {}
                    rel = edge_data.get("relationship")
                    if rel in ("CROSS_ZONE_IAM_PATH", "ACCESSES_DATA_STORE", "CAN_ACCESS"):
                        target_node = self.dt.get_node(neighbor)
                        if target_node:
                            cascading_reason = (
                                f"Overprivileged policy attachment on '{role_node.id}' satisfies "
                                f"{rel} blast condition: potentially exposes sensitive "
                                f"data in '{target_node.id}' to cross-bucket read/write access if "
                                f"execution credentials are compromised"
                            )
                            c_path = [role_node.id, neighbor]
                            c_rels = [rel]
                            self._record_impact(
                                impacted=impacted,
                                node=target_node,
                                tier=BlastTier.CASCADING,
                                reason=cascading_reason,
                                path=c_path,
                                relationships=c_rels,
                                trigger=res_label,
                            )
                            # Downstream data asset and encryption key traversal
                            self._propagate_datastore_impact(
                                target_node, c_path, c_rels, res_label, impacted
                            )
                    elif rel in ("ASSUMES_CROSS_ACCOUNT_ROLE", "CROSS_ACCOUNT_TRUST"):
                        target_role = self.dt.get_node(neighbor)
                        if target_role:
                            self._record_impact(
                                impacted=impacted,
                                node=target_role,
                                tier=BlastTier.CASCADING,
                                reason=(
                                    f"Cross-account trust allows overprivileged role '{role_node.id}' "
                                    f"to assume target role '{target_role.id}' across AWS account boundaries"
                                ),
                                path=[role_node.id, neighbor],
                                relationships=[rel],
                                trigger=res_label,
                            )

                # 3. Cascading: Workloads that assume this role (Reverse lookup of ASSUMES_ROLE)
                for predecessor in self.graph.predecessors(role_node.id):
                    edge_data = self.graph.get_edge_data(predecessor, role_node.id) or {}
                    p_rel = edge_data.get("relationship")
                    if p_rel in ("ASSUMES_ROLE", "IRSA_TRUST", "ASSUMES_POD_IDENTITY"):
                        workload_node = self.dt.get_node(predecessor)
                        if workload_node:
                            p_path = [role_node.id, predecessor]
                            p_rels = ["ASSUMES_ROLE_REVERSE"]
                            self._record_impact(
                                impacted=impacted,
                                node=workload_node,
                                tier=BlastTier.CASCADING,
                                reason=(
                                    f"Workload '{workload_node.id}' assumes newly overprivileged role "
                                    f"'{role_node.id}', potentially acquiring broad cloud API capabilities"
                                ),
                                path=p_path,
                                relationships=p_rels,
                                trigger=res_label,
                            )
                            self._propagate_workload_impact(
                                workload_node, p_path, p_rels, res_label, impacted
                            )
        return True

    def _propagate_workload_impact(
        self,
        workload_node: TopologyNode,
        current_path: List[str],
        current_rels: List[str],
        trigger: str,
        impacted: Dict[str, ImpactedNode],
    ) -> None:
        """Propagate cascading impact from an impacted workload to its hosted applications."""
        if not self.graph.has_node(workload_node.id):
            return
        for succ in self.graph.successors(workload_node.id):
            edge_data = self.graph.get_edge_data(workload_node.id, succ) or {}
            rel = edge_data.get("relationship")
            if rel in ("HOSTS_APPLICATION", "RUNS_APPLICATION"):
                app_node = self.dt.get_node(succ)
                if app_node:
                    reason = (
                        f"Business application '{app_node.name}' hosted on impacted workload "
                        f"'{workload_node.id}' is potentially exposed to compromise or service disruption"
                    )
                    self._record_impact(
                        impacted=impacted,
                        node=app_node,
                        tier=BlastTier.CASCADING,
                        reason=reason,
                        path=current_path + [succ],
                        relationships=current_rels + [rel],
                        trigger=trigger,
                    )

    def _propagate_datastore_impact(
        self,
        datastore_node: TopologyNode,
        current_path: List[str],
        current_rels: List[str],
        trigger: str,
        impacted: Dict[str, ImpactedNode],
    ) -> None:
        """Propagate cascading impact from an impacted storage/database to sensitive data assets and encryption keys."""
        if not self.graph.has_node(datastore_node.id):
            return
        for succ in self.graph.successors(datastore_node.id):
            edge_data = self.graph.get_edge_data(datastore_node.id, succ) or {}
            rel = edge_data.get("relationship")
            if rel == "STORES_DATA":
                data_node = self.dt.get_node(succ)
                if data_node:
                    class_info = f" ({data_node.data_classification})" if data_node.data_classification else ""
                    reason = (
                        f"Sensitive data asset '{data_node.name}'{class_info} stored in '{datastore_node.id}' "
                        f"is potentially exposed to unauthorized access, tampering, or exfiltration"
                    )
                    self._record_impact(
                        impacted=impacted,
                        node=data_node,
                        tier=BlastTier.CASCADING,
                        reason=reason,
                        path=current_path + [succ],
                        relationships=current_rels + [rel],
                        trigger=trigger,
                    )
            elif rel == "ENCRYPTED_BY":
                kms_node = self.dt.get_node(succ)
                if kms_node:
                    reason = (
                        f"KMS encryption key '{kms_node.name}' protecting '{datastore_node.id}' "
                        f"is associated with potentially exposed data store"
                    )
                    self._record_impact(
                        impacted=impacted,
                        node=kms_node,
                        tier=BlastTier.CASCADING,
                        reason=reason,
                        path=current_path + [succ],
                        relationships=current_rels + [rel],
                        trigger=trigger,
                    )

    def _record_impact(
        self,
        impacted: Dict[str, ImpactedNode],
        node: TopologyNode,
        tier: BlastTier,
        reason: str,
        path: List[str],
        relationships: List[str],
        trigger: str,
    ) -> None:
        """Record or promote an impacted node. Direct impact always supersedes cascading."""
        if node.id in impacted:
            existing = impacted[node.id]
            # If newly evaluated as DIRECT but previously CASCADING, promote to DIRECT
            if tier == BlastTier.DIRECT and existing.tier == BlastTier.CASCADING:
                impacted[node.id] = ImpactedNode(
                    node_id=node.id,
                    node_name=node.name,
                    node_type=node.type,
                    criticality=node.criticality,
                    status=ImpactStatus.AFFECTED,
                    tier=BlastTier.DIRECT,
                    impact_reason=reason,
                    path_from_trigger=path,
                    relationships_traversed=relationships,
                    trigger_resource=trigger,
                )
            return

        impacted[node.id] = ImpactedNode(
            node_id=node.id,
            node_name=node.name,
            node_type=node.type,
            criticality=node.criticality,
            status=ImpactStatus.AFFECTED,
            tier=tier,
            impact_reason=reason,
            path_from_trigger=path,
            relationships_traversed=relationships,
            trigger_resource=trigger,
        )
