"""Enterprise Demo Dataset Loader and Compiler for SimuGuard AI.

Loads the Apex Global Technologies modular dataset, verifies referential
integrity across network, cloud, IAM, and application domains, and compiles
the data into a DigitalTwinGraph.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field
from simuguard.graph.digital_twin import (
    DigitalTwinGraph,
    DigitalTwinTopology,
    TopologyEdge,
    TopologyMetadata,
    TopologyNode,
)
from simuguard.models.enums import AssetCriticality


class DatasetValidationReport(BaseModel):
    """Validation report verifying referential integrity across the dataset."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool = True
    total_nodes: int = 0
    total_edges: int = 0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    node_type_counts: Dict[str, int] = Field(default_factory=dict)
    relationship_counts: Dict[str, int] = Field(default_factory=dict)
    unresolved_edges: List[Dict[str, str]] = Field(default_factory=list)


class EnterpriseDatasetLoader:
    """Ingests, validates, and compiles the Apex Global Technologies dataset."""

    def __init__(self, demo_env_dir: Optional[Path] = None):
        if demo_env_dir:
            self.base_dir = Path(demo_env_dir).resolve()
        else:
            # Default to demo_environment relative to repository root
            pkg_root = Path(__file__).parent.parent.parent.resolve()
            self.base_dir = pkg_root / "demo_environment"

    def _read_json(self, rel_path: str) -> Dict[str, Any]:
        """Read and parse a JSON file within the dataset directory."""
        file_path = self.base_dir / rel_path
        if not file_path.is_file():
            raise FileNotFoundError(f"Dataset file missing: {file_path}")
        return json.loads(file_path.read_text(encoding="utf-8"))

    def validate_dataset(self) -> DatasetValidationReport:
        """Perform comprehensive referential integrity and consistency checks."""
        report = DatasetValidationReport()

        try:
            org = self._read_json("organisation.json")
            fw_data = self._read_json("network/firewalls.json")
            pan_data = self._read_json("network/panorama.json")
            zones_data = self._read_json("network/zones.json")
            subnets_data = self._read_json("network/subnets.json")
            policies_data = self._read_json("network/security_policies.json")
            addrs_data = self._read_json("network/address_objects.json")
            services_data = self._read_json("network/service_objects.json")
            accounts_data = self._read_json("cloud/accounts.json")
            vpcs_data = self._read_json("cloud/vpcs.json")
            sgs_data = self._read_json("cloud/security_groups.json")
            resources_data = self._read_json("cloud/resources.json")
            identities_data = self._read_json("iam/identities.json")
            roles_data = self._read_json("iam/roles.json")
            policies_iam = self._read_json("iam/policies.json")
            apps_data = self._read_json("applications/applications.json")
            data_assets = self._read_json("data_assets/assets.json")
            classifications = self._read_json("data_assets/classifications.json")
            edges_data = self._read_json("relationships/topology_edges.json")

            # SailPoint Identity Security Cloud dataset (Phase 3.7)
            sp_dir = self.base_dir / "sailpoint"
            sp_tenant = None
            sp_sources = None
            sp_idps = None
            sp_identities = None
            sp_accounts = None
            sp_entitlements = None
            sp_access_profiles = None
            sp_roles = None
            sp_requests = None
            sp_approvals = None
            sp_certifications = None
            sp_provisioning = None
            sp_edges = None
            if sp_dir.is_dir():
                sp_tenant = self._read_json("sailpoint/tenant.json")
                sp_sources = self._read_json("sailpoint/sources.json")
                sp_idps = self._read_json("sailpoint/identity_profiles.json")
                sp_identities = self._read_json("sailpoint/identities.json")
                sp_accounts = self._read_json("sailpoint/accounts.json")
                sp_entitlements = self._read_json("sailpoint/entitlements.json")
                sp_access_profiles = self._read_json("sailpoint/access_profiles.json")
                sp_roles = self._read_json("sailpoint/roles.json")
                sp_requests = self._read_json("sailpoint/access_requests.json")
                sp_approvals = self._read_json("sailpoint/approvals.json")
                sp_certifications = self._read_json("sailpoint/certifications.json")
                sp_provisioning = self._read_json("sailpoint/provisioning_events.json")
                sp_edges = self._read_json("sailpoint/relationships.json")
        except Exception as exc:
            report.is_valid = False
            report.errors.append(f"Failed to load dataset files: {exc}")
            return report

        # 1. Collect all node IDs and check uniqueness
        all_ids: Set[str] = set()

        def register_id(uid: str, category: str):
            if uid in all_ids:
                report.errors.append(f"Duplicate identifier '{uid}' found in {category}")
                report.is_valid = False
            all_ids.add(uid)

        # Firewalls & Panorama
        register_id(pan_data["panorama"]["server_id"], "Panorama")
        for fw in fw_data.get("firewalls", []):
            register_id(fw["id"], "Firewalls")

        # Zones & Subnets
        for z in zones_data.get("zones", []):
            register_id(z["id"], "Zones")
            # Also register name as an alias for zone lookups
            all_ids.add(z["name"])
        for s in subnets_data.get("subnets", []):
            register_id(s["id"], "Subnets")

        # Cloud Accounts
        for acc in accounts_data.get("accounts", []):
            acc_id = acc.get("id") or acc.get("account_id")
            if acc_id:
                register_id(acc_id, "Cloud_Accounts")

        # Cloud Compute, DBs, Storage, Load Balancers, KMS
        for c in resources_data.get("compute_workloads", []):
            register_id(c["id"], "Compute_Workloads")
        for lb in resources_data.get("load_balancers", []):
            register_id(lb["id"], "Load_Balancers")
        for db in resources_data.get("databases", []):
            register_id(db["id"], "Databases")
        for b in resources_data.get("storage_buckets", []):
            register_id(b["id"], "Storage_Buckets")
        for k in resources_data.get("kms_keys", []):
            register_id(k["id"], "KMS_Keys")

        # IAM Identities & Roles
        for ident in identities_data.get("identities", []):
            register_id(ident["id"], "IAM_Identities")
        for r in roles_data.get("roles", []):
            # If role id equals name, register
            if r["id"] not in all_ids:
                register_id(r["id"], "IAM_Roles")

        # Applications & Data Assets
        for app in apps_data.get("applications", []):
            register_id(app["id"], "Applications")
        for da in data_assets.get("data_assets", []):
            register_id(da["id"], "Data_Assets")

        # SailPoint Governance Entities (Phase 3.7)
        if sp_dir.is_dir() and sp_tenant:
            register_id(sp_tenant["tenant"]["id"], "SailPoint_Tenant")
            for src in sp_sources.get("sources", []):
                register_id(src["id"], "SailPoint_Sources")
            for idp in sp_idps.get("identity_profiles", []):
                register_id(idp["id"], "SailPoint_IdentityProfiles")
            for ident in sp_identities.get("identities", []):
                register_id(ident["id"], "SailPoint_Identities")
            for acct in sp_accounts.get("accounts", []):
                register_id(acct["id"], "SailPoint_Accounts")
            for ent in sp_entitlements.get("entitlements", []):
                register_id(ent["id"], "SailPoint_Entitlements")
            for ap in sp_access_profiles.get("access_profiles", []):
                register_id(ap["id"], "SailPoint_AccessProfiles")
            for role in sp_roles.get("roles", []):
                register_id(role["id"], "SailPoint_Roles")
            for req in sp_requests.get("access_requests", []):
                register_id(req["id"], "SailPoint_AccessRequests")
            for appr in sp_approvals.get("approvals", []):
                register_id(appr["id"], "SailPoint_Approvals")
            for cert in sp_certifications.get("certifications", []):
                register_id(cert["id"], "SailPoint_Certifications")
            for prov in sp_provisioning.get("provisioning_events", []):
                register_id(prov["id"], "SailPoint_ProvisioningEvents")

        report.total_nodes = len(all_ids)

        # 2. Check relationship referential integrity (sources & targets must exist)
        all_edges_to_validate = list(edges_data.get("edges", []))
        if sp_dir.is_dir() and sp_edges:
            all_edges_to_validate.extend(sp_edges.get("relationships", []))

        for edge in all_edges_to_validate:
            src = edge.get("source")
            tgt = edge.get("target")
            rel = edge.get("relationship", "UNKNOWN")
            report.relationship_counts[rel] = report.relationship_counts.get(rel, 0) + 1

            unresolved = False
            if src not in all_ids:
                report.errors.append(f"Edge source '{src}' does not exist in dataset (relationship: {rel})")
                report.is_valid = False
                unresolved = True
            if tgt not in all_ids:
                report.errors.append(f"Edge target '{tgt}' does not exist in dataset (relationship: {rel})")
                report.is_valid = False
                unresolved = True
            if unresolved:
                report.unresolved_edges.append({"source": str(src), "target": str(tgt), "relationship": rel})

        report.total_edges = len(all_edges_to_validate)

        # 3. Verify Applications workload references
        for app in apps_data.get("applications", []):
            for w in app.get("associated_workloads", []):
                if w not in all_ids:
                    report.errors.append(f"Application '{app['id']}' references unknown workload '{w}'")
                    report.is_valid = False

        # 4. Verify Sensitive Data Asset Classifications
        valid_classifications = {c["tier"] for c in classifications.get("classifications", [])}
        for da in data_assets.get("data_assets", []):
            c_tier = da.get("classification")
            if c_tier not in valid_classifications:
                report.errors.append(f"Data Asset '{da['id']}' has invalid classification '{c_tier}'")
                report.is_valid = False

        # 5. Verify Firewall Rules zone references
        valid_zone_names = {z["name"] for z in zones_data.get("zones", [])}
        valid_zone_names.add("any")
        for pol in policies_data.get("policies", []):
            for sz in pol.get("source_zones", []):
                if sz not in valid_zone_names:
                    report.errors.append(f"Policy '{pol['id']}' references unknown source zone '{sz}'")
                    report.is_valid = False
            for dz in pol.get("destination_zones", []):
                if dz not in valid_zone_names:
                    report.errors.append(f"Policy '{pol['id']}' references unknown destination zone '{dz}'")
                    report.is_valid = False

        # 6. Verify SailPoint Semantic Referential Integrity
        if sp_dir.is_dir() and sp_tenant:
            known_sources = {s["id"] for s in sp_sources.get("sources", [])}
            known_identities = {i["id"] for i in sp_identities.get("identities", [])}
            known_idps = {p["id"] for p in sp_idps.get("identity_profiles", [])}
            known_accounts = {a["id"] for a in sp_accounts.get("accounts", [])}
            known_entitlements = {e["id"] for e in sp_entitlements.get("entitlements", [])}
            known_aps = {ap["id"] for ap in sp_access_profiles.get("access_profiles", [])}
            known_requests = {r["id"] for r in sp_requests.get("access_requests", [])}
            known_approvals = {a["id"] for a in sp_approvals.get("approvals", [])}

            # Accounts must reference valid source and identity
            for acct in sp_accounts.get("accounts", []):
                if acct["source_id"] not in known_sources:
                    report.errors.append(f"SailPoint account '{acct['id']}' references unknown source '{acct['source_id']}'")
                    report.is_valid = False
                if acct["identity_id"] not in known_identities:
                    report.errors.append(f"SailPoint account '{acct['id']}' references unknown identity '{acct['identity_id']}'")
                    report.is_valid = False

            # Identities must reference valid identity profile
            for ident in sp_identities.get("identities", []):
                if ident.get("identity_profile_id") and ident["identity_profile_id"] not in known_idps:
                    report.errors.append(f"Identity '{ident['id']}' references unknown profile '{ident['identity_profile_id']}'")
                    report.is_valid = False

            # Access profiles must reference valid source and entitlements
            for ap in sp_access_profiles.get("access_profiles", []):
                if ap["source_id"] not in known_sources:
                    report.errors.append(f"Access profile '{ap['id']}' references unknown source '{ap['source_id']}'")
                    report.is_valid = False
                for ent_id in ap.get("entitlements", []):
                    if ent_id not in known_entitlements:
                        report.errors.append(f"Access profile '{ap['id']}' references unknown entitlement '{ent_id}'")
                        report.is_valid = False

            # Roles must reference valid access profiles
            for role in sp_roles.get("roles", []):
                for ap_id in role.get("access_profiles", []):
                    if ap_id not in known_aps:
                        report.errors.append(f"Role '{role['id']}' references unknown access profile '{ap_id}'")
                        report.is_valid = False

            # Entitlements must reference valid source
            for ent in sp_entitlements.get("entitlements", []):
                if ent["source_id"] not in known_sources:
                    report.errors.append(f"Entitlement '{ent['id']}' references unknown source '{ent['source_id']}'")
                    report.is_valid = False

        return report

    def compile_digital_twin_topology(self) -> DigitalTwinTopology:
        """Compile the modular dataset into a unified DigitalTwinTopology."""
        org = self._read_json("organisation.json")
        fw_data = self._read_json("network/firewalls.json")
        pan_data = self._read_json("network/panorama.json")
        zones_data = self._read_json("network/zones.json")
        subnets_data = self._read_json("network/subnets.json")
        resources_data = self._read_json("cloud/resources.json")
        roles_data = self._read_json("iam/roles.json")
        apps_data = self._read_json("applications/applications.json")
        data_assets = self._read_json("data_assets/assets.json")
        edges_data = self._read_json("relationships/topology_edges.json")

        metadata = TopologyMetadata(
            organization=org["name"],
            firewall_vendor="Palo Alto Networks (PAN-OS 11.1 Nebula)",
            perimeter_firewall="fw-edge-01-primary",
            compliance_frameworks=org.get("compliance_frameworks", []),
        )

        nodes: List[TopologyNode] = []

        # 1. Panorama
        pan = pan_data["panorama"]
        nodes.append(
            TopologyNode(
                id=pan["server_id"],
                name=pan["hostname"],
                type="Panorama_Server",
                criticality=AssetCriticality.CRITICAL,
            )
        )

        # 2. Firewalls
        for fw in fw_data.get("firewalls", []):
            nodes.append(
                TopologyNode(
                    id=fw["id"],
                    name=fw["name"],
                    type="NGFW_Palo_Alto",
                    criticality=AssetCriticality(fw.get("criticality", "Critical")),
                    zones=fw.get("enforced_zones", []),
                    threat_prevention_profile=(
                        fw.get("active_threat_profiles", ["Strict-Enterprise-Security"])[0]
                    ),
                )
            )

        # 3. Zones
        for z in zones_data.get("zones", []):
            nodes.append(
                TopologyNode(
                    id=z["id"],
                    name=f"Zone: {z['name']}",
                    type="Network_Zone",
                    criticality=AssetCriticality(z.get("criticality", "High")),
                    contains=z.get("subnet_cidrs", []),
                )
            )

        # 4. Subnets
        for s in subnets_data.get("subnets", []):
            nodes.append(
                TopologyNode(
                    id=s["id"],
                    name=f"Subnet: {s['name']} ({s['cidr_block']})",
                    type="Network_Subnet",
                    criticality=AssetCriticality.HIGH,
                )
            )

        # 5. Cloud Workloads
        for c in resources_data.get("compute_workloads", []):
            nodes.append(
                TopologyNode(
                    id=c["id"],
                    name=c["name"],
                    type=c.get("type", "Compute_Cluster"),
                    criticality=AssetCriticality(c.get("criticality", "High")),
                    attached_iam_role=c.get("attached_iam_role"),
                    security_groups=[c.get("security_group_id")] if c.get("security_group_id") else [],
                )
            )

        # 6. Load Balancers
        for lb in resources_data.get("load_balancers", []):
            nodes.append(
                TopologyNode(
                    id=lb["id"],
                    name=lb["name"],
                    type="Load_Balancer_ALB",
                    criticality=AssetCriticality.HIGH,
                )
            )

        # 7. Databases
        for db in resources_data.get("databases", []):
            nodes.append(
                TopologyNode(
                    id=db["id"],
                    name=db["name"],
                    type=db.get("type", "Database_RDS_PostgreSQL"),
                    criticality=AssetCriticality(db.get("criticality", "Critical")),
                    data_classification=db.get("data_classification"),
                )
            )

        # 8. Storage Buckets
        for b in resources_data.get("storage_buckets", []):
            nodes.append(
                TopologyNode(
                    id=b["id"],
                    name=b["name"],
                    type="Storage_S3_Bucket",
                    criticality=AssetCriticality(b.get("criticality", "Critical")),
                    data_classification=b.get("data_classification"),
                    compliance_controls=b.get("compliance_controls", []),
                )
            )

        # 9. KMS Keys
        for k in resources_data.get("kms_keys", []):
            nodes.append(
                TopologyNode(
                    id=k["id"],
                    name=k["alias"],
                    type="KMS_Key",
                    criticality=AssetCriticality.HIGH,
                )
            )

        # 10. IAM Roles
        for r in roles_data.get("roles", []):
            nodes.append(
                TopologyNode(
                    id=r["id"],
                    name=r["arn"].split("/")[-1],
                    type="IAM_Role",
                    criticality=AssetCriticality(r.get("criticality", "High")),
                    current_policies=r.get("attached_policies", []),
                )
            )

        # 11. Applications
        for a in apps_data.get("applications", []):
            nodes.append(
                TopologyNode(
                    id=a["id"],
                    name=a["name"],
                    type="Business_Application",
                    criticality=AssetCriticality(a.get("criticality", "High")),
                    data_classification=a.get("data_classification"),
                )
            )

        # 12. Sensitive Data Assets
        for da in data_assets.get("data_assets", []):
            nodes.append(
                TopologyNode(
                    id=da["id"],
                    name=da["name"],
                    type="Data_Asset",
                    criticality=AssetCriticality(da.get("criticality", "Critical")),
                    data_classification=da.get("classification"),
                    compliance_controls=da.get("compliance_controls", []),
                )
            )

        # 13. Cloud Accounts
        accounts_data = self._read_json("cloud/accounts.json")
        for acc in accounts_data.get("accounts", []):
            acc_id = acc.get("id") or acc.get("account_id")
            if acc_id:
                nodes.append(
                    TopologyNode(
                        id=acc_id,
                        name=acc.get("name", acc_id),
                        type="Cloud_Account",
                        criticality=AssetCriticality(acc.get("criticality", "High")),
                    )
                )

        # 14. SailPoint Identity Security Cloud Entities (Phase 3.7)
        sp_dir = self.base_dir / "sailpoint"
        if sp_dir.is_dir():
            sp_tenant = self._read_json("sailpoint/tenant.json")
            sp_sources = self._read_json("sailpoint/sources.json")
            sp_idps = self._read_json("sailpoint/identity_profiles.json")
            sp_identities = self._read_json("sailpoint/identities.json")
            sp_accounts = self._read_json("sailpoint/accounts.json")
            sp_entitlements = self._read_json("sailpoint/entitlements.json")
            sp_access_profiles = self._read_json("sailpoint/access_profiles.json")
            sp_roles = self._read_json("sailpoint/roles.json")
            sp_requests = self._read_json("sailpoint/access_requests.json")
            sp_approvals = self._read_json("sailpoint/approvals.json")
            sp_certifications = self._read_json("sailpoint/certifications.json")
            sp_provisioning = self._read_json("sailpoint/provisioning_events.json")

            # Tenant
            nodes.append(
                TopologyNode(
                    id=sp_tenant["tenant"]["id"],
                    name=sp_tenant["tenant"]["name"],
                    type="SailPoint_Tenant",
                    criticality=AssetCriticality.CRITICAL,
                )
            )

            # Sources
            for src in sp_sources.get("sources", []):
                nodes.append(
                    TopologyNode(
                        id=src["id"],
                        name=src["name"],
                        type="SailPoint_Source",
                        criticality=AssetCriticality.HIGH,
                    )
                )

            # Identity Profiles
            for idp in sp_idps.get("identity_profiles", []):
                nodes.append(
                    TopologyNode(
                        id=idp["id"],
                        name=idp["name"],
                        type="SailPoint_IdentityProfile",
                        criticality=AssetCriticality.HIGH,
                    )
                )

            # Identities
            for ident in sp_identities.get("identities", []):
                nodes.append(
                    TopologyNode(
                        id=ident["id"],
                        name=ident["display_name"],
                        type="SailPoint_Identity",
                        criticality=AssetCriticality(ident.get("risk_classification", "High")),
                    )
                )

            # Accounts
            for acct in sp_accounts.get("accounts", []):
                crit = AssetCriticality.HIGH if acct.get("privileged") else AssetCriticality.MEDIUM
                nodes.append(
                    TopologyNode(
                        id=acct["id"],
                        name=acct["account_name"],
                        type="SailPoint_Account",
                        criticality=crit,
                    )
                )

            # Roles
            for role in sp_roles.get("roles", []):
                nodes.append(
                    TopologyNode(
                        id=role["id"],
                        name=role["name"],
                        type="SailPoint_Role",
                        criticality=AssetCriticality.HIGH,
                    )
                )

            # Access Profiles
            for ap in sp_access_profiles.get("access_profiles", []):
                crit = AssetCriticality.HIGH if ap.get("privileged") else AssetCriticality.MEDIUM
                nodes.append(
                    TopologyNode(
                        id=ap["id"],
                        name=ap["name"],
                        type="SailPoint_AccessProfile",
                        criticality=crit,
                    )
                )

            # Entitlements
            for ent in sp_entitlements.get("entitlements", []):
                nodes.append(
                    TopologyNode(
                        id=ent["id"],
                        name=ent["name"],
                        type="SailPoint_Entitlement",
                        criticality=AssetCriticality(ent.get("risk_level", "High")),
                    )
                )

            # Access Requests
            for req in sp_requests.get("access_requests", []):
                nodes.append(
                    TopologyNode(
                        id=req["id"],
                        name=req["id"],
                        type="SailPoint_AccessRequest",
                        criticality=AssetCriticality.MEDIUM,
                    )
                )

            # Approvals
            for appr in sp_approvals.get("approvals", []):
                nodes.append(
                    TopologyNode(
                        id=appr["id"],
                        name=appr["id"],
                        type="SailPoint_Approval",
                        criticality=AssetCriticality.MEDIUM,
                    )
                )

            # Certifications
            for cert in sp_certifications.get("certifications", []):
                nodes.append(
                    TopologyNode(
                        id=cert["id"],
                        name=cert["campaign_name"],
                        type="SailPoint_Certification",
                        criticality=AssetCriticality.HIGH,
                    )
                )

            # Provisioning Events
            for prov in sp_provisioning.get("provisioning_events", []):
                nodes.append(
                    TopologyNode(
                        id=prov["id"],
                        name=prov["id"],
                        type="SailPoint_ProvisioningEvent",
                        criticality=AssetCriticality.MEDIUM,
                    )
                )

        # Edges
        edges: List[TopologyEdge] = []
        for e in edges_data.get("edges", []):
            edges.append(
                TopologyEdge(
                    source=e["source"],
                    target=e["target"],
                    relationship=e["relationship"],
                    blast_condition=e.get("blast_condition"),
                )
            )

        # SailPoint Governance Relationships (Phase 3.7)
        if sp_dir.is_dir():
            sp_edges = self._read_json("sailpoint/relationships.json")
            for e in sp_edges.get("relationships", []):
                edges.append(
                    TopologyEdge(
                        source=e["source"],
                        target=e["target"],
                        relationship=e["relationship"],
                        blast_condition=e.get("blast_condition"),
                    )
                )

        return DigitalTwinTopology(
            metadata=metadata,
            nodes=nodes,
            edges=edges,
        )

    def load_as_digital_twin_graph(self) -> DigitalTwinGraph:
        """Compile the dataset and load it directly into a DigitalTwinGraph instance."""
        compiled = self.compile_digital_twin_topology()

        # Build SG mapping registry from resources
        resources_data = self._read_json("cloud/resources.json")
        sg_map: Dict[str, str] = {}
        for c in resources_data.get("compute_workloads", []):
            sg_id = c.get("security_group_id")
            if sg_id:
                sg_map[sg_id] = c["id"]

        return DigitalTwinGraph(topology=compiled, sg_mappings=sg_map)

    def load_sailpoint_governance(self) -> Dict[str, Any]:
        """Load and return all raw SailPoint governance data dictionaries."""
        sp_dir = self.base_dir / "sailpoint"
        if not sp_dir.is_dir():
            return {}
        return {
            "tenant": self._read_json("sailpoint/tenant.json"),
            "sources": self._read_json("sailpoint/sources.json"),
            "identity_profiles": self._read_json("sailpoint/identity_profiles.json"),
            "identities": self._read_json("sailpoint/identities.json"),
            "accounts": self._read_json("sailpoint/accounts.json"),
            "entitlements": self._read_json("sailpoint/entitlements.json"),
            "access_profiles": self._read_json("sailpoint/access_profiles.json"),
            "roles": self._read_json("sailpoint/roles.json"),
            "access_requests": self._read_json("sailpoint/access_requests.json"),
            "approvals": self._read_json("sailpoint/approvals.json"),
            "certifications": self._read_json("sailpoint/certifications.json"),
            "provisioning_events": self._read_json("sailpoint/provisioning_events.json"),
            "relationships": self._read_json("sailpoint/relationships.json"),
        }

    def get_all_resource_ids(self) -> List[str]:
        """Collect all unique primary resource identifiers declared across the dataset."""
        ids: List[str] = []
        try:
            fw_data = self._read_json("network/firewalls.json")
            pan_data = self._read_json("network/panorama.json")
            zones_data = self._read_json("network/zones.json")
            subnets_data = self._read_json("network/subnets.json")
            accounts_data = self._read_json("cloud/accounts.json")
            resources_data = self._read_json("cloud/resources.json")
            identities_data = self._read_json("iam/identities.json")
            roles_data = self._read_json("iam/roles.json")
            apps_data = self._read_json("applications/applications.json")
            data_assets = self._read_json("data_assets/assets.json")

            ids.append(pan_data["panorama"]["server_id"])
            ids.extend([fw["id"] for fw in fw_data.get("firewalls", [])])
            ids.extend([z["id"] for z in zones_data.get("zones", [])])
            ids.extend([s["id"] for s in subnets_data.get("subnets", [])])
            for acc in accounts_data.get("accounts", []):
                acc_id = acc.get("id") or acc.get("account_id")
                if acc_id and acc_id not in ids:
                    ids.append(acc_id)
            ids.extend([c["id"] for c in resources_data.get("compute_workloads", [])])
            ids.extend([lb["id"] for lb in resources_data.get("load_balancers", [])])
            ids.extend([db["id"] for db in resources_data.get("databases", [])])
            ids.extend([b["id"] for b in resources_data.get("storage_buckets", [])])
            ids.extend([k["id"] for k in resources_data.get("kms_keys", [])])
            ids.extend([ident["id"] for ident in identities_data.get("identities", [])])
            ids.extend([r["id"] for r in roles_data.get("roles", []) if r["id"] not in ids])
            ids.extend([a["id"] for a in apps_data.get("applications", [])])
            ids.extend([da["id"] for da in data_assets.get("data_assets", [])])

            # SailPoint identifiers
            sp_dir = self.base_dir / "sailpoint"
            if sp_dir.is_dir():
                sp_tenant = self._read_json("sailpoint/tenant.json")
                sp_sources = self._read_json("sailpoint/sources.json")
                sp_idps = self._read_json("sailpoint/identity_profiles.json")
                sp_identities = self._read_json("sailpoint/identities.json")
                sp_accounts = self._read_json("sailpoint/accounts.json")
                sp_entitlements = self._read_json("sailpoint/entitlements.json")
                sp_access_profiles = self._read_json("sailpoint/access_profiles.json")
                sp_roles = self._read_json("sailpoint/roles.json")
                sp_requests = self._read_json("sailpoint/access_requests.json")
                sp_approvals = self._read_json("sailpoint/approvals.json")
                sp_certifications = self._read_json("sailpoint/certifications.json")
                sp_provisioning = self._read_json("sailpoint/provisioning_events.json")

                ids.append(sp_tenant["tenant"]["id"])
                ids.extend([src["id"] for src in sp_sources.get("sources", [])])
                ids.extend([idp["id"] for idp in sp_idps.get("identity_profiles", [])])
                ids.extend([ident["id"] for ident in sp_identities.get("identities", [])])
                ids.extend([acct["id"] for acct in sp_accounts.get("accounts", [])])
                ids.extend([ent["id"] for ent in sp_entitlements.get("entitlements", [])])
                ids.extend([ap["id"] for ap in sp_access_profiles.get("access_profiles", [])])
                ids.extend([role["id"] for role in sp_roles.get("roles", [])])
                ids.extend([req["id"] for req in sp_requests.get("access_requests", [])])
                ids.extend([appr["id"] for appr in sp_approvals.get("approvals", [])])
                ids.extend([cert["id"] for cert in sp_certifications.get("certifications", [])])
                ids.extend([prov["id"] for prov in sp_provisioning.get("provisioning_events", [])])
        except Exception:
            pass
        return ids
