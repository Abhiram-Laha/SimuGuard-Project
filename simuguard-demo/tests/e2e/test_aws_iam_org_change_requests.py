"""End-to-End Regression Test Suite for Apex Global Technologies AWS IAM Organization Change Requests.

Tests all five realistic organization-aligned IAM change requests against the
authoritative IAM Digital Twin data (identities.json, roles.json, policies.json,
trust_relationships.json, and resource_policies.json).

Test Scenarios:
1. CHG-IAM-2026-2101: Analytics Workload Managed S3 Full Access (IAM-01 Overprivilege + Boundary Check)
2. CHG-IAM-2026-2102: Dev to Production Cross-Account Trust Change (IAM-02 Insecure Trust without MFA)
3. CHG-IAM-2026-2103: Customer Portal Backend AdministratorAccess (IAM-01 Catastrophic Overprivilege + IAM-05 Expiry)
4. CHG-IAM-2026-2104: PCI Payment Processor Permission Boundary Removal (IAM-03 Boundary Degradation)
5. CHG-IAM-2026-2105: SecOps Incident Response MFA Cross-Account Review (IAM-06 Verified MFA Audit Path)
"""

import os
import sqlite3
import tempfile
import pytest
from typing import Dict, Any

from ui.services.servicenow_extractor import ServiceNowExtractor
from simuguard.identity.resolver import CentralizedIdentityResolver
from ui.services.assessment_runner import AssessmentRunnerService
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.models.enums import DeploymentVerdict, Severity, AssetCriticality, BlastTier
from storage.database import init_db
from storage.repository import ChangeRepository
from storage.models import (
    SailPointChangeDetails,
    ChangeRequestRecord,
    ChangeDomain,
    ChangeType,
)


@pytest.fixture(scope="module")
def iam_data():
    """Load authoritative AWS IAM governance data."""
    return EnterpriseDatasetLoader().load_aws_iam_governance()


@pytest.fixture(scope="module")
def resolver(iam_data):
    """Initialize centralized identity resolver with IAM digital twin data."""
    return CentralizedIdentityResolver(iam_data=iam_data)


@pytest.fixture
def temp_repo():
    """Provide isolated SQLite database for assessment runs."""
    temp_db = tempfile.mktemp(suffix=".db")
    init_db(temp_db)
    repo = ChangeRepository(db_path=temp_db)
    yield repo
    if os.path.exists(temp_db):
        try:
            os.remove(temp_db)
        except OSError:
            pass


def _load_ticket(filename: str) -> str:
    path = os.path.join("SimuGuard_Realistic_Org_Change_Requests", filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _run_ticket_assessment(repo: ChangeRepository, text: str):
    """Helper to parse, persist, and run assessment through standard workflow."""
    cfg = ServiceNowExtractor.extract_from_text(text)
    sp_details = SailPointChangeDetails(
        identity_name=cfg.target_role_name or cfg.role_name,
        account_id=cfg.aws_account,
        current_department="Cloud Infrastructure",
        requested_role=cfg.requested_policy_name or cfg.requested_role or cfg.target_role_name,
        access_to_add=cfg.access_to_add,
        access_to_remove=cfg.access_to_remove,
        privileged_access_requested=cfg.privileged_access_requested,
        privileged_entitlements=cfg.privileged_entitlements,
        business_justification=cfg.justification,
        approval_status=cfg.approval_status or "PENDING",
        lifecycle_type=cfg.lifecycle_type,
        role_name=cfg.role_name,
        role_arn=cfg.role_arn,
        target_role_name=cfg.target_role_name,
        target_role_arn=cfg.target_role_arn,
        source_role_name=cfg.source_role_name,
        source_role_arn=cfg.source_role_arn,
        source_identity_record_id=cfg.source_identity_record_id,
        requested_policy_name=cfg.requested_policy_name,
        identity_record_id=cfg.identity_record_id,
        aws_account=cfg.aws_account,
        source_aws_account=cfg.source_aws_account,
        target_aws_account=cfg.target_aws_account,
        assigned_workload=cfg.assigned_workload,
        current_attached_policies=cfg.current_attached_policies,
        permission_boundary=cfg.permission_boundary,
        permission_boundary_arn=cfg.permission_boundary_arn,
        boundary_action=cfg.boundary_action,
        trust_relationship_id=cfg.trust_relationship_id,
        trusted_principal=cfg.trusted_principal,
        mfa_condition=cfg.mfa_condition,
        external_id_condition=cfg.external_id_condition,
    )
    record = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        change_type=ChangeType.AWS_IAM.value,
        justification=cfg.justification,
        priority=cfg.priority or "NORMAL",
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    repo.create_change_request(record)
    runner = AssessmentRunnerService(repository=repo)
    success, msg, result = runner.run_assessment(cfg.request_number)
    assert success, f"Assessment execution failed: {msg}"
    return cfg, sp_details, result


# =====================================================================
# Test 1: CHG-IAM-2026-2101 (Analytics Role Overprivilege)
# =====================================================================
def test_iam_01_analytics_role_overprivilege(resolver, temp_repo):
    text = _load_ticket("01_IAM_Analytics_Role_Overprivilege.txt")
    cfg, sp_details, result = _run_ticket_assessment(temp_repo, text)

    # 1. Extraction verification
    assert cfg.request_number == "CHG-IAM-2026-2101"
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.role_name == "role-analytics-ingestion-svc"
    assert cfg.role_arn == "arn:aws:iam::111122223333:role/role-analytics-ingestion-svc"
    assert cfg.identity_record_id == "ident-role-analytics-ingestion-svc"
    assert cfg.aws_account == "111122223333"
    assert cfg.assigned_workload == "eks-analytics-worker-pool"
    assert cfg.requested_policy_name == "AmazonS3FullAccess"
    assert cfg.permission_boundary == "ApexWorkloadBoundary"
    assert cfg.approval_status == "PENDING"
    assert "S3TelemetryWriteOnly" in cfg.current_attached_policies

    # 2. Identity resolution verification
    res = resolver.resolve_identity(
        query=cfg.role_name,
        identifier=cfg.identity_record_id,
        account_id=cfg.aws_account,
    )
    assert res.status.value == "RESOLVED"
    assert res.identity["arn"] == cfg.role_arn
    assert res.identity["id"] == "ident-role-analytics-ingestion-svc"

    # 3. Assessment rules and verdict
    report = result.baseline_report
    assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    rule_ids = [g.rule_id for g in report.identified_security_gaps]
    assert "IAM-01" in rule_ids
    assert "IAM-04" in rule_ids  # In-flight pending approvals
    assert "IAM-05" in rule_ids  # Missing temporary expiry

    # Verify boundary note in IAM-01 description
    iam_01_gap = next(g for g in report.identified_security_gaps if g.rule_id == "IAM-01")
    assert "ApexWorkloadBoundary" in iam_01_gap.technical_impact
    assert "corp-restricted-cui-financial-vault" in iam_01_gap.technical_impact

    # 4. Affected assets verification (Direct + Cascading)
    asset_ids = [a.asset_id for a in report.predicted_affected_assets]
    assert "role-analytics-ingestion-svc" in asset_ids
    assert "s3-enterprise-cui-vault" in asset_ids
    assert "s3-dev-staging-telemetry" in asset_ids
    assert "eks-analytics-worker-pool" in asset_ids


# =====================================================================
# Test 2: CHG-IAM-2026-2102 (Dev to Production Trust Change)
# =====================================================================
def test_iam_02_dev_to_production_trust_change(resolver, temp_repo):
    text = _load_ticket("02_IAM_Dev_To_Production_Trust_Change.txt")
    cfg, sp_details, result = _run_ticket_assessment(temp_repo, text)

    # 1. Extraction verification
    assert cfg.request_number == "CHG-IAM-2026-2102"
    assert cfg.role_name == "role-ci-cd-deployment-pipeline"
    assert cfg.role_arn == "arn:aws:iam::111122223333:role/role-ci-cd-deployment-pipeline"
    assert cfg.source_role_name == "role-dev-developer-sandbox"
    assert cfg.source_aws_account == "222233334444"
    assert cfg.trust_relationship_id == "trust-excessive-dev-to-prod"
    assert "not configured" in cfg.mfa_condition.lower()
    assert cfg.permission_boundary.lower() in ["none", ""]

    # 2. Identity resolution verification
    res = resolver.resolve_identity(
        query=cfg.role_name,
        identifier=cfg.identity_record_id,
        account_id=cfg.aws_account,
    )
    assert res.status.value == "RESOLVED"
    assert res.identity["arn"] == cfg.role_arn

    # 3. Assessment rules and verdict
    report = result.baseline_report
    assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    rule_ids = [g.rule_id for g in report.identified_security_gaps]
    assert "IAM-02" in rule_ids
    assert "IAM-04" in rule_ids

    # 4. Affected assets verification
    asset_ids = [a.asset_id for a in report.predicted_affected_assets]
    assert "role-ci-cd-deployment-pipeline" in asset_ids
    assert "role-dev-developer-sandbox" in asset_ids
    assert "svc-github-actions-runner" in asset_ids


# =====================================================================
# Test 3: CHG-IAM-2026-2103 (Customer Portal Admin Policy Request)
# =====================================================================
def test_iam_03_customer_portal_admin_policy(resolver, temp_repo):
    text = _load_ticket("03_IAM_Customer_Portal_Admin_Policy_Request.txt")
    cfg, sp_details, result = _run_ticket_assessment(temp_repo, text)

    # 1. Extraction verification
    assert cfg.request_number == "CHG-IAM-2026-2103"
    assert cfg.role_name == "role-customer-portal-backend"
    assert cfg.role_arn == "arn:aws:iam::111122223333:role/role-customer-portal-backend"
    assert cfg.identity_record_id == "ident-role-customer-portal-backend"
    assert cfg.assigned_workload == "eks-customer-portal-cluster"
    assert cfg.requested_policy_name == "AdministratorAccess"
    assert cfg.permission_boundary == "ApexWorkloadBoundary"
    assert "CustomerPortalDatabaseAccess" in cfg.current_attached_policies

    # 2. Identity resolution verification
    res = resolver.resolve_identity(
        query=cfg.role_name,
        identifier=cfg.identity_record_id,
        account_id=cfg.aws_account,
    )
    assert res.status.value == "RESOLVED"
    assert res.identity["arn"] == cfg.role_arn

    # 3. Assessment rules and verdict
    report = result.baseline_report
    assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    assert report.overall_risk_score == 100  # Catastrophic
    rule_ids = [g.rule_id for g in report.identified_security_gaps]
    assert "IAM-01" in rule_ids
    assert "IAM-04" in rule_ids
    assert "IAM-05" in rule_ids

    # Verify boundary does not override catastrophic finding
    iam_01_gap = next(g for g in report.identified_security_gaps if g.rule_id == "IAM-01")
    assert iam_01_gap.severity == Severity.CRITICAL
    assert "ApexWorkloadBoundary" in iam_01_gap.technical_impact

    # 4. Affected assets verification
    asset_ids = [a.asset_id for a in report.predicted_affected_assets]
    assert "role-customer-portal-backend" in asset_ids
    assert "rds-postgres-core-prod" in asset_ids
    assert "eks-customer-portal-cluster" in asset_ids


# =====================================================================
# Test 4: CHG-IAM-2026-2104 (PCI Boundary Removal Request)
# =====================================================================
def test_iam_04_pci_boundary_removal(resolver, temp_repo):
    text = _load_ticket("04_IAM_PCI_Boundary_Removal_Request.txt")
    cfg, sp_details, result = _run_ticket_assessment(temp_repo, text)

    # 1. Extraction verification
    assert cfg.request_number == "CHG-IAM-2026-2104"
    assert cfg.role_name == "role-payment-processor-pci"
    assert cfg.role_arn == "arn:aws:iam::111122223333:role/role-payment-processor-pci"
    assert cfg.identity_record_id == "ident-role-payment-processor-pci"
    assert cfg.assigned_workload == "eks-payment-processor-pool"
    assert cfg.permission_boundary == "ApexStrictPCIBoundary"
    assert cfg.boundary_action == "REMOVE"
    assert "PCITokenVaultAccess" in cfg.current_attached_policies
    assert "KmsDecryptPaymentScoped" in cfg.current_attached_policies

    # 2. Identity resolution verification
    res = resolver.resolve_identity(
        query=cfg.role_name,
        identifier=cfg.identity_record_id,
        account_id=cfg.aws_account,
    )
    assert res.status.value == "RESOLVED"
    assert res.identity["arn"] == cfg.role_arn

    # 3. Assessment rules and verdict
    report = result.baseline_report
    assert report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    rule_ids = [g.rule_id for g in report.identified_security_gaps]
    assert "IAM-03" in rule_ids
    assert "IAM-04" in rule_ids

    # 4. Affected assets verification (PCI Token Vault, KMS, Compute)
    asset_ids = [a.asset_id for a in report.predicted_affected_assets]
    assert "role-payment-processor-pci" in asset_ids
    assert "rds-pci-token-vault-prod" in asset_ids
    assert "k-pci-token-encryption" in asset_ids
    assert "eks-payment-processor-pool" in asset_ids


# =====================================================================
# Test 5: CHG-IAM-2026-2105 (SecOps Cross-Account MFA Review)
# =====================================================================
def test_iam_05_secops_cross_account_mfa_review(resolver, temp_repo):
    text = _load_ticket("05_IAM_SecOps_Cross_Account_MFA_Review.txt")
    cfg, sp_details, result = _run_ticket_assessment(temp_repo, text)

    # 1. Extraction verification
    assert cfg.request_number == "CHG-IAM-2026-2105"
    assert cfg.role_name == "role-secops-audit-agent"
    assert cfg.role_arn == "arn:aws:iam::111122223333:role/role-secops-audit-agent"
    assert cfg.source_role_name == "role-secops-incident-responder"
    assert cfg.source_role_arn == "arn:aws:iam::333344445555:role/role-secops-incident-responder"
    assert cfg.source_identity_record_id == "ident-role-secops-incident-responder"
    assert cfg.source_aws_account == "333344445555"
    assert cfg.target_aws_account == "111122223333"
    assert cfg.trust_relationship_id == "trust-secops-cross-account-prod"
    assert "aws:MultiFactorAuthPresent = true" in cfg.mfa_condition

    # 2. Identity resolution verification (Cross-Account Target Role)
    res = resolver.resolve_identity(
        query=cfg.role_name,
        identifier=cfg.identity_record_id,
        account_id=cfg.aws_account,
    )
    assert res.status.value == "RESOLVED"
    assert res.identity["arn"] == cfg.role_arn

    # Also resolve source identity
    src_res = resolver.resolve_identity(
        query=cfg.source_role_name,
        identifier=cfg.source_identity_record_id,
        account_id=cfg.source_aws_account,
    )
    assert src_res.status.value == "RESOLVED"
    assert src_res.identity["arn"] == cfg.source_role_arn

    # 3. Assessment rules and verdict (Controlled Validation Scenario)
    report = result.baseline_report
    assert report.deployment_verdict == DeploymentVerdict.ALLOW
    assert report.overall_risk_score <= 10
    rule_ids = [g.rule_id for g in report.identified_security_gaps]
    assert "IAM-06" in rule_ids  # Routine review pending
    assert "IAM-01" not in rule_ids
    assert "IAM-02" not in rule_ids
    assert "IAM-03" not in rule_ids

    # 4. Affected assets verification (Both source responder and target audit agent)
    asset_ids = [a.asset_id for a in report.predicted_affected_assets]
    assert "role-secops-audit-agent" in asset_ids
    assert "role-secops-incident-responder" in asset_ids
    assert "ec2-sec-siem-forwarder" in asset_ids


# =====================================================================
# Database Isolation Verification
# =====================================================================
def test_simuguard_history_db_isolation():
    """Verify that testing did not leak any rows into the production database."""
    db_path = os.path.join("simuguard-demo", "data", "simuguard_history.db")
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for table in ["change_requests", "assessment_records", "remediation_records", "activity_logs"]:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        assert count == 0, f"Production table '{table}' contains {count} leaked rows!"
    conn.close()
