"""Comprehensive Automated Test Suite for Phase 3.7: SailPoint Identity Governance.

Validates:
1. test_identity_to_account_mapping: Verify identities map to multiple accounts (OWNS_ACCOUNT), and identity != account entity.
2. test_identity_to_role_mapping: Verify identities map to roles (MEMBER_OF_ROLE).
3. test_role_to_access_profile_mapping: Verify roles group access profiles (HAS_ACCESS_PROFILE).
4. test_access_profile_to_entitlement_mapping: Verify access profiles group entitlements (CONTAINS_ENTITLEMENT).
5. test_entitlement_to_source_mapping: Verify entitlements map to valid sources.
6. test_access_request_approval_state: Verify request approval lifecycle states (APPROVED, REJECTED, PENDING_APPROVAL, REVOKED).
7. test_provisioning_state: Verify distinction between REQUESTED_NOT_PROVISIONED, PROVISIONED, and FAILED.
8. test_certification_state: Verify certification decisions (APPROVED, REVOKED, PENDING_REVIEW, EXPIRED).
9. test_sailpoint_to_aws_governance_relationships: Verify SailPoint sources govern AWS accounts (GOVERNED_BY_SAILPOINT).
10. test_retained_aws_infrastructure: Verify AWS VPCs, subnets, SGs, EKS, RDS, S3, KMS, and IAM roles are completely preserved.
11. test_network_to_identity_to_resource_traversal: Verify end-to-end traversal from Identity -> Role -> AP -> Entitlement -> S3 Bucket -> CUI Data Asset, and Network Engineer -> Panorama.
12. test_unknown_identity_and_resource_mappings: Verify unmapped identities or accounts produce UNKNOWN status.
13. test_no_accidental_conversion_of_pending_access: Verify pending access requests do NOT grant effective access or traverse to resources.
14. test_no_accidental_deletion_of_aws_resource_permissions: Verify AWS resource-level permissions and IAM policies remain intact in the database.
"""

import json
from pathlib import Path
import networkx as nx
import pytest

from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph
from simuguard.graph.blast_radius import BlastRadiusAnalyzer
from simuguard.models.enums import AssetCriticality, BlastTier, ImpactStatus
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo_environment"
SP_DIR = DEMO_DIR / "sailpoint"


@pytest.fixture
def dataset_loader() -> EnterpriseDatasetLoader:
    return EnterpriseDatasetLoader(DEMO_DIR)


@pytest.fixture
def enterprise_twin(dataset_loader: EnterpriseDatasetLoader) -> DigitalTwinGraph:
    return dataset_loader.load_as_digital_twin_graph()


@pytest.fixture
def sp_data(dataset_loader: EnterpriseDatasetLoader):
    return dataset_loader.load_sailpoint_governance()


class TestSailPointIdentityGovernance:
    """Automated test suite verifying SailPoint Identity Security Cloud integration."""

    def test_identity_to_account_mapping(self, sp_data, enterprise_twin: DigitalTwinGraph):
        """Test 1: Verify identities map to multiple accounts (OWNS_ACCOUNT), and identity != account entity."""
        identities = sp_data["identities"]["identities"]
        accounts = sp_data["accounts"]["accounts"]
        graph = enterprise_twin.nx_graph

        # Collect accounts per identity
        accts_by_ident = {}
        for acct in accounts:
            ident_id = acct["identity_id"]
            accts_by_ident.setdefault(ident_id, []).append(acct["id"])

        # Check multi-account ownership (identity != account)
        # Sarah Chen has AD, Entra ID, and AWS SecOps accounts
        sarah_accts = accts_by_ident.get("sp-ident-sarah-chen", [])
        assert len(sarah_accts) >= 3, f"Sarah Chen must have >= 3 accounts, found: {sarah_accts}"
        assert "sp-acct-ad-sarah-chen" in sarah_accts
        assert "sp-acct-entra-sarah-chen" in sarah_accts
        assert "sp-acct-aws-secops-sarah-chen" in sarah_accts

        # Verify identity entity is distinct from account entities in graph
        ident_node = enterprise_twin.get_node("sp-ident-sarah-chen")
        assert ident_node is not None
        assert ident_node.type == "SailPoint_Identity"

        acct_node = enterprise_twin.get_node("sp-acct-aws-secops-sarah-chen")
        assert acct_node is not None
        assert acct_node.type == "SailPoint_Account"
        assert ident_node.id != acct_node.id

        # Verify OWNS_ACCOUNT relationship in graph
        for ident_id, acct_id in [
            ("sp-ident-emily-watson", "sp-acct-apps-emily-watson"),
            ("sp-ident-david-kim", "sp-acct-pan-david-kim"),
            ("sp-ident-alex-morgan", "sp-acct-aws-prod-alex-morgan"),
        ]:
            assert graph.has_edge(ident_id, acct_id), f"Graph missing edge: {ident_id} -> {acct_id}"
            edge_data = graph.get_edge_data(ident_id, acct_id)
            assert edge_data["relationship"] == "OWNS_ACCOUNT"

    def test_identity_to_role_mapping(self, sp_data, enterprise_twin: DigitalTwinGraph):
        """Test 2: Verify identities map to roles (MEMBER_OF_ROLE)."""
        roles = sp_data["roles"]["roles"]
        graph = enterprise_twin.nx_graph

        role_assignments = {}
        for r in roles:
            for ident_id in r.get("assigned_identities", []):
                role_assignments.setdefault(ident_id, []).append(r["id"])

        # Emily Watson -> Finance Analyst
        assert "sp-role-finance-analyst" in role_assignments.get("sp-ident-emily-watson", [])
        # David Kim -> Network Security Engineer
        assert "sp-role-network-security-engineer" in role_assignments.get("sp-ident-david-kim", [])
        # Alex Morgan -> Cloud Administrator
        assert "sp-role-cloud-administrator" in role_assignments.get("sp-ident-alex-morgan", [])

        # Verify graph edges
        assert graph.has_edge("sp-ident-emily-watson", "sp-role-finance-analyst")
        assert graph.get_edge_data("sp-ident-emily-watson", "sp-role-finance-analyst")["relationship"] == "MEMBER_OF_ROLE"

        assert graph.has_edge("sp-ident-david-kim", "sp-role-network-security-engineer")
        assert graph.get_edge_data("sp-ident-david-kim", "sp-role-network-security-engineer")["relationship"] == "MEMBER_OF_ROLE"

    def test_role_to_access_profile_mapping(self, sp_data, enterprise_twin: DigitalTwinGraph):
        """Test 3: Verify roles group access profiles (HAS_ACCESS_PROFILE)."""
        roles = sp_data["roles"]["roles"]
        graph = enterprise_twin.nx_graph

        role_ap_map = {r["id"]: r.get("access_profiles", []) for r in roles}

        # Finance Analyst groups S3 Read access profile
        assert "sp-ap-aws-prod-s3-read" in role_ap_map["sp-role-finance-analyst"]
        # Network Security Engineer groups Palo Alto Firewall Admin access profile
        assert "sp-ap-paloalto-firewall-admin" in role_ap_map["sp-role-network-security-engineer"]
        # Cloud Administrator groups AWS Prod Admin access profile
        assert "sp-ap-aws-prod-admin" in role_ap_map["sp-role-cloud-administrator"]

        # Verify graph edges
        assert graph.has_edge("sp-role-finance-analyst", "sp-ap-aws-prod-s3-read")
        assert graph.get_edge_data("sp-role-finance-analyst", "sp-ap-aws-prod-s3-read")["relationship"] == "HAS_ACCESS_PROFILE"

        assert graph.has_edge("sp-role-network-security-engineer", "sp-ap-paloalto-firewall-admin")
        assert graph.get_edge_data("sp-role-network-security-engineer", "sp-ap-paloalto-firewall-admin")["relationship"] == "HAS_ACCESS_PROFILE"

    def test_access_profile_to_entitlement_mapping(self, sp_data, enterprise_twin: DigitalTwinGraph):
        """Test 4: Verify access profiles group entitlements (CONTAINS_ENTITLEMENT)."""
        aps = sp_data["access_profiles"]["access_profiles"]
        graph = enterprise_twin.nx_graph

        ap_ent_map = {ap["id"]: ap.get("entitlements", []) for ap in aps}

        # Production S3 Read AP contains S3 CUI Read entitlement
        assert "sp-ent-aws-s3-cui-read" in ap_ent_map["sp-ap-aws-prod-s3-read"]
        # Firewall Admin AP contains PanOS Admin Write entitlement
        assert "sp-ent-panos-admin-write" in ap_ent_map["sp-ap-paloalto-firewall-admin"]

        # Verify graph edges
        assert graph.has_edge("sp-ap-aws-prod-s3-read", "sp-ent-aws-s3-cui-read")
        assert graph.get_edge_data("sp-ap-aws-prod-s3-read", "sp-ent-aws-s3-cui-read")["relationship"] == "CONTAINS_ENTITLEMENT"

        assert graph.has_edge("sp-ap-paloalto-firewall-admin", "sp-ent-panos-admin-write")
        assert graph.get_edge_data("sp-ap-paloalto-firewall-admin", "sp-ent-panos-admin-write")["relationship"] == "CONTAINS_ENTITLEMENT"

    def test_entitlement_to_source_mapping(self, sp_data):
        """Test 5: Verify entitlements map to valid sources."""
        sources = {s["id"] for s in sp_data["sources"]["sources"]}
        entitlements = sp_data["entitlements"]["entitlements"]

        assert len(entitlements) >= 10
        for ent in entitlements:
            assert ent["source_id"] in sources, f"Entitlement {ent['id']} has invalid source {ent['source_id']}"

        # Specific source assertions
        s3_read_ent = next(e for e in entitlements if e["id"] == "sp-ent-aws-s3-cui-read")
        assert s3_read_ent["source_id"] == "sp-src-aws-prod"
        assert s3_read_ent["target_resource_id"] == "s3-enterprise-cui-vault"

        pan_ent = next(e for e in entitlements if e["id"] == "sp-ent-panos-admin-write")
        assert pan_ent["source_id"] == "sp-src-firewall-mgmt"
        assert pan_ent["target_resource_id"] == "pan-mgmt-01"

    def test_access_request_approval_state(self, sp_data):
        """Test 6: Verify request approval lifecycle states (APPROVED, REJECTED, PENDING_APPROVAL, REVOKED)."""
        requests = {r["id"]: r for r in sp_data["access_requests"]["access_requests"]}
        approvals = {a["id"]: a for a in sp_data["approvals"]["approvals"]}

        # 1. APPROVED request
        req_approved = requests["sp-req-1001-approved-s3-read"]
        assert req_approved["status"] == "APPROVED"
        assert req_approved["effective_access_granted"] is True
        appr1 = approvals[req_approved["approval_id"]]
        assert appr1["decision"] == "APPROVED"
        assert appr1["decision_timestamp"] is not None

        # 2. REJECTED request
        req_rejected = requests["sp-req-1002-rejected-prod-admin"]
        assert req_rejected["status"] == "REJECTED"
        assert req_rejected["effective_access_granted"] is False
        appr2 = approvals[req_rejected["approval_id"]]
        assert appr2["decision"] == "REJECTED"

        # 3. PENDING_APPROVAL request
        req_pending = requests["sp-req-1003-pending-admin-access"]
        assert req_pending["status"] == "PENDING_APPROVAL"
        assert req_pending["effective_access_granted"] is False
        assert req_pending["decision_date"] is None
        appr3 = approvals[req_pending["approval_id"]]
        assert appr3["decision"] == "PENDING"
        assert appr3["decision_timestamp"] is None

        # 4. EMERGENCY_BREAK_GLASS request
        req_emergency = requests["sp-req-1004-emergency-firewall-access"]
        assert req_emergency["request_type"] == "EMERGENCY_BREAK_GLASS"
        assert req_emergency["status"] == "APPROVED"
        assert req_emergency["expiration_date"] is not None

        # 5. REVOKE_ACCESS request
        req_revoke = requests["sp-req-1005-revocation-contractor"]
        assert req_revoke["request_type"] == "REVOKE_ACCESS"
        assert req_revoke["status"] == "APPROVED"
        assert req_revoke["provisioning_status"] == "SUCCESSFULLY_REVOKED"

    def test_provisioning_state(self, sp_data):
        """Test 7: Verify distinction between REQUESTED_NOT_PROVISIONED, PROVISIONED, and FAILED."""
        events = {e["id"]: e for e in sp_data["provisioning_events"]["provisioning_events"]}

        # 1. PROVISIONED state: Synchronized and confirmed on target
        ev_prov = events["sp-prov-2001-grant-s3-read"]
        assert ev_prov["state"] == "PROVISIONED"
        assert ev_prov["reconciliation_status"] == "VERIFIED_ON_SOURCE"

        # 2. REQUESTED_NOT_PROVISIONED state: Blocked behind approval gate
        ev_pending = events["sp-prov-2004-pending-admin-grant"]
        assert ev_pending["state"] == "REQUESTED_NOT_PROVISIONED"
        assert ev_pending["reconciliation_status"] == "AWAITING_APPROVAL"

        # 3. FAILED state: Provisioning attempt failed and requires retry
        ev_failed = events["sp-prov-2005-failed-provisioning-retry"]
        assert ev_failed["state"] == "FAILED"
        assert ev_failed["reconciliation_status"] == "RETRY_QUEUED"

    def test_certification_state(self, sp_data):
        """Test 8: Verify certification decisions (APPROVED, REVOKED, PENDING_REVIEW, EXPIRED)."""
        certs = {c["id"]: c for c in sp_data["certifications"]["certifications"]}

        # 1. APPROVED certification
        cert_appr = certs["sp-cert-2026-q1-privileged-access"]
        assert cert_appr["decision"] == "APPROVED"
        assert cert_appr["certification_status"] == "COMPLETED"

        # 2. REVOKED certification
        cert_rev = certs["sp-cert-2025-q4-dormant-revoked"]
        assert cert_rev["decision"] == "REVOKED"
        assert cert_rev["certification_status"] == "COMPLETED"

        # 3. PENDING_REVIEW certification
        cert_pending = certs["sp-cert-2026-q2-contractor-review"]
        assert cert_pending["decision"] == "PENDING_REVIEW"
        assert cert_pending["certification_status"] == "ACTIVE_CAMPAIGN"
        assert cert_pending["decision_timestamp"] is None

        # 4. EXPIRED certification
        cert_exp = certs["sp-cert-2026-q1-expired-emergency"]
        assert cert_exp["decision"] == "EXPIRED"
        assert cert_exp["certification_status"] == "COMPLETED"

    def test_sailpoint_to_aws_governance_relationships(self, enterprise_twin: DigitalTwinGraph):
        """Test 9: Verify SailPoint sources govern AWS accounts (GOVERNED_BY_SAILPOINT)."""
        graph = enterprise_twin.nx_graph

        # Verify AWS accounts are governed by SailPoint sources
        expected_governance = [
            ("sp-src-aws-prod", "111122223333"),
            ("sp-src-aws-dev", "222233334444"),
            ("sp-src-aws-secops", "333344445555"),
            ("sp-src-firewall-mgmt", "pan-mgmt-01"),
        ]

        for src, tgt in expected_governance:
            assert graph.has_edge(src, tgt), f"Missing governance edge: {src} -> {tgt}"
            edge_data = graph.get_edge_data(src, tgt)
            assert edge_data["relationship"] == "GOVERNED_BY_SAILPOINT"

    def test_retained_aws_infrastructure(self, dataset_loader: EnterpriseDatasetLoader, enterprise_twin: DigitalTwinGraph):
        """Test 10: Verify AWS VPCs, subnets, SGs, EKS, RDS, S3, KMS, and IAM roles are completely preserved."""
        # 1. AWS Accounts preserved
        accounts = dataset_loader._read_json("cloud/accounts.json")["accounts"]
        assert len(accounts) == 3
        account_ids = {a["id"] for a in accounts}
        assert account_ids == {"111122223333", "222233334444", "333344445555"}

        # 2. AWS VPCs preserved
        vpcs = dataset_loader._read_json("cloud/vpcs.json")["vpcs"]
        assert len(vpcs) == 3
        vpc_ids = {v["id"] for v in vpcs}
        assert vpc_ids == {"vpc-prod-us-east-1", "vpc-dev-us-east-1", "vpc-sec-us-east-1"}

        # 3. Subnets preserved
        subnets = dataset_loader._read_json("network/subnets.json")["subnets"]
        assert len(subnets) == 9

        # 4. Security Groups preserved
        sgs = dataset_loader._read_json("cloud/security_groups.json")["security_groups"]
        assert len(sgs) >= 7

        # 5. Resources preserved (EKS, RDS, S3, KMS)
        resources = dataset_loader._read_json("cloud/resources.json")
        compute = {c["id"] for c in resources["compute_workloads"]}
        assert "eks-customer-portal-cluster" in compute
        assert "eks-analytics-worker-pool" in compute
        assert "eks-payment-processor-pool" in compute

        dbs = {d["id"] for d in resources["databases"]}
        assert "rds-postgres-core-prod" in dbs
        assert "rds-pci-token-vault-prod" in dbs

        buckets = {b["id"] for b in resources["storage_buckets"]}
        assert "s3-enterprise-cui-vault" in buckets
        assert "s3-pci-audit-records-prod" in buckets

        kms = {k["id"] for k in resources["kms_keys"]}
        assert "kms-cui-vault" in kms
        assert "kms-pci-token" in kms

        # 6. IAM Roles preserved
        roles = dataset_loader._read_json("iam/roles.json")["roles"]
        role_ids = {r["id"] for r in roles}
        assert "role-analytics-ingestion-svc" in role_ids
        assert "role-customer-portal-backend" in role_ids
        assert "role-payment-processor-pci" in role_ids
        assert "role-ci-cd-deployment-pipeline" in role_ids
        assert "role-dev-developer-sandbox" in role_ids

    def test_network_to_identity_to_resource_traversal(self, enterprise_twin: DigitalTwinGraph):
        """Test 11: Verify end-to-end traversal from Identity -> Role -> AP -> Entitlement -> S3 Bucket -> CUI Data Asset, and Network Engineer -> Panorama."""
        graph = enterprise_twin.nx_graph

        # Path 1: Identity (Emily Watson) -> Role -> Access Profile -> Entitlement -> S3 Bucket -> Sensitive Data Asset
        path1_nodes = [
            "sp-ident-emily-watson",
            "sp-role-finance-analyst",
            "sp-ap-aws-prod-s3-read",
            "sp-ent-aws-s3-cui-read",
            "s3-enterprise-cui-vault",
            "DATA-01-CUI-FINANCIAL-VAULT",
        ]

        for i in range(len(path1_nodes) - 1):
            u, v = path1_nodes[i], path1_nodes[i + 1]
            assert graph.has_edge(u, v), f"Missing edge in identity governance path: {u} -> {v}"

        assert nx.has_path(graph, "sp-ident-emily-watson", "DATA-01-CUI-FINANCIAL-VAULT")
        all_paths1 = list(nx.all_simple_paths(graph, "sp-ident-emily-watson", "DATA-01-CUI-FINANCIAL-VAULT"))
        assert path1_nodes in all_paths1

        # Path 2: Network Engineer Identity (David Kim) -> Role -> Access Profile -> Entitlement -> Panorama Management Server
        path2_nodes = [
            "sp-ident-david-kim",
            "sp-role-network-security-engineer",
            "sp-ap-paloalto-firewall-admin",
            "sp-ent-panos-admin-write",
            "pan-mgmt-01",
        ]

        for i in range(len(path2_nodes) - 1):
            u, v = path2_nodes[i], path2_nodes[i + 1]
            assert graph.has_edge(u, v), f"Missing edge in network engineer path: {u} -> {v}"

        assert nx.has_path(graph, "sp-ident-david-kim", "pan-mgmt-01")
        all_paths2 = list(nx.all_simple_paths(graph, "sp-ident-david-kim", "pan-mgmt-01"))
        assert path2_nodes in all_paths2

    def test_unknown_identity_and_resource_mappings(self, enterprise_twin: DigitalTwinGraph):
        """Test 12: Verify unmapped identities or accounts produce UNKNOWN status."""
        analyzer = BlastRadiusAnalyzer(enterprise_twin)

        # Simulate an unmapped security group rule referencing an unknown security group
        unmapped_rule = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="unmapped_external_access",
            source_file="simulated_change.tf",
            rule_type="ingress",
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-unknown-identity-proxy-999",
        )

        result = analyzer.analyze_resources([unmapped_rule])

        # Must flag unmapped resource with UNKNOWN status
        assert len(result.unmapped_resources) > 0
        assert len(result.unknown_impacts) > 0
        assert result.unknown_impacts[0].status == ImpactStatus.UNKNOWN

        # Cannot declare unaffected nodes as confirmed safe
        assert len(result.not_affected_nodes) == 0
        assert len(result.unknown_nodes) > 0

    def test_no_accidental_conversion_of_pending_access(self, sp_data, enterprise_twin: DigitalTwinGraph):
        """Test 13: Verify pending access requests do NOT grant effective access or traverse to resources."""
        requests = {r["id"]: r for r in sp_data["access_requests"]["access_requests"]}
        graph = enterprise_twin.nx_graph

        pending_req = requests["sp-req-1003-pending-admin-access"]
        assert pending_req["status"] == "PENDING_APPROVAL"
        assert pending_req["effective_access_granted"] is False

        requester = pending_req["requester_identity_id"]  # sp-ident-vikram-sharma
        requested_role = pending_req["requested_item_id"]  # sp-role-cloud-administrator

        # Vikram Sharma must NOT have MEMBER_OF_ROLE to the requested role
        assert not graph.has_edge(requester, requested_role), (
            f"Governance violation: Pending request granted role membership: {requester} -> {requested_role}"
        )

        # Vikram Sharma must NOT be able to traverse to AWS Prod Root Admin or S3 CUI Vault
        assert not nx.has_path(graph, requester, "sp-ent-aws-prod-root-admin")
        assert not nx.has_path(graph, requester, "s3-enterprise-cui-vault")

    def test_no_accidental_deletion_of_aws_resource_permissions(self, dataset_loader: EnterpriseDatasetLoader):
        """Test 14: Verify AWS resource-level permissions and IAM policies remain intact in the database."""
        policies_data = dataset_loader._read_json("iam/policies.json")
        policies = policies_data.get("policies", [])

        assert len(policies) >= 6
        policy_arns = {p["arn"] for p in policies}

        # Verify critical AWS customer-managed resource policies exist intact
        assert "arn:aws:iam::111122223333:policy/S3TelemetryWriteOnly" in policy_arns
        assert "arn:aws:iam::111122223333:policy/PCITokenVaultAccess" in policy_arns
        assert "arn:aws:iam::111122223333:policy/CustomerPortalDatabaseAccess" in policy_arns
        assert "arn:aws:iam::111122223333:policy/ApexWorkloadBoundary" in policy_arns
        assert "arn:aws:iam::111122223333:policy/ApexStrictPCIBoundary" in policy_arns
        assert "arn:aws:iam::111122223333:policy/KmsDecryptPaymentScoped" in policy_arns

        # Verify statements contain granular actions and resource constraints
        telemetry_policy = next(p for p in policies if "S3TelemetryWriteOnly" in p["arn"])
        actions = telemetry_policy["document"]["Statement"][0]["Action"]
        assert "s3:PutObject" in actions
        assert "s3:AbortMultipartUpload" in actions
        # Least privilege: DeleteObject is prohibited for ingestion writer
        assert "s3:DeleteObject" not in actions

        # Customer portal policy includes read/write
        portal_policy = next(p for p in policies if "CustomerPortalDatabaseAccess" in p["arn"])
        portal_actions = portal_policy["document"]["Statement"][0]["Action"]
        assert "s3:GetObject" in portal_actions
        assert "s3:PutObject" in portal_actions
