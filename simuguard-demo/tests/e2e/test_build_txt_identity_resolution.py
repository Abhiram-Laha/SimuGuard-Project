"""E2E & Integration Tests for SailPoint Dynamic Identity Resolution (build.txt REQ-05)."""

import json
from pathlib import Path
import tempfile
import pytest
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.identity import (
    CentralizedIdentityResolver,
    IdentityAccessState,
    IdentityLifecycleCategory,
    IdentityResolutionResult,
    IdentityResolutionStatus,
)
from storage.database import init_db
from storage.models import ChangeDomain, ChangeRequestRecord, SailPointChangeDetails
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService


@pytest.fixture
def temp_repo():
    """Isolated temporary SQLite repository for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


@pytest.fixture
def sp_loader() -> EnterpriseDatasetLoader:
    return EnterpriseDatasetLoader()


@pytest.fixture
def sp_data(sp_loader) -> dict:
    return sp_loader.load_sailpoint_governance()


@pytest.fixture
def resolver(sp_data) -> CentralizedIdentityResolver:
    return CentralizedIdentityResolver(sp_data)


def test_identity_resolution_dynamic_and_not_hardcoded(resolver: CentralizedIdentityResolver):
    """Verify resolver dynamically correlates diverse identities across the dataset without hardcoding."""
    test_cases = [
        ("David Kim", "sp-ident-david-kim", IdentityLifecycleCategory.ACTIVE_EMPLOYEE),
        ("Elena Rodriguez", "sp-ident-elena-rodriguez", IdentityLifecycleCategory.ACTIVE_EMPLOYEE),
        ("Marcus Vance", "sp-ident-marcus-vance", IdentityLifecycleCategory.ACTIVE_EMPLOYEE),
        ("Ananya Rao", "sp-ident-ananya-rao", IdentityLifecycleCategory.ACTIVE_EMPLOYEE),
        ("Sophia Alvarez", "sp-ident-sophia-alvarez", IdentityLifecycleCategory.CONTRACTOR),
        ("Liam O'Connor", "sp-ident-liam-oconnor", IdentityLifecycleCategory.CONTRACTOR),
    ]
    for query, expected_id, expected_cat in test_cases:
        res = resolver.resolve_identity(query)
        assert res.status == IdentityResolutionStatus.RESOLVED, f"Failed for {query}: {res.message}"
        assert res.identity_id == expected_id, f"Expected {expected_id}, got {res.identity_id}"
        assert res.lifecycle_category == expected_cat


def test_unmapped_identity_never_defaults_to_sarah_chen_or_any_user(resolver: CentralizedIdentityResolver):
    """Verify unmapped or unknown identity never falls back to Sarah Chen or any default identity."""
    unmapped_names = ["Unknown Ghost User", "Random Intern", "NonExistentEntity_99", "Rahul Sharma"]
    for name in unmapped_names:
        res = resolver.resolve_identity(name)
        assert res.status == IdentityResolutionStatus.UNMAPPED, f"Expected UNMAPPED for {name}, got {res.status}"
        assert res.identity is None
        assert res.identity_id is None
        assert "cannot be correlated" in res.message


def test_contractor_onboarding_and_privileged_access_block(temp_repo: ChangeRepository):
    """Verify contractor requesting privileged administrative access triggers SP-04 BLOCK."""
    sp_details = SailPointChangeDetails(
        identity_name="Sophia Alvarez",
        requested_role="Cloud Infrastructure Administrator",
        request_status="APPROVED",
        approval_status="APPROVED",
        provisioning_status="PROVISIONED",
    )
    record = ChangeRequestRecord(
        request_number="REQ-SP-CONTRACTOR-01",
        title="Contractor Cloud Admin Request",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    temp_repo.create_change_request(record)
    runner = AssessmentRunnerService(temp_repo)
    ok, msg, result = runner.run_assessment(record.request_number)
    assert ok and result is not None

    assert result.baseline_report.deployment_verdict.value == "BLOCK_DEPLOYMENT"
    rule_ids = [g.rule_id for g in result.baseline_report.identified_security_gaps]
    assert "SP-04" in rule_ids, "Contractor requesting admin role must trigger SP-04"


def test_terminated_leaver_identity_access_request_block(temp_repo: ChangeRepository):
    """Verify access request for a terminated / leaver identity triggers critical SP-05 BLOCK."""
    # Inject a leaver identity into mock dataset
    custom_sp_data = {
        "identities": {
            "identities": [
                {
                    "id": "sp-ident-leaver-user",
                    "display_name": "Terminated Staff",
                    "email": "leaver@example.com",
                    "employment_type": "EMPLOYEE",
                    "lifecycle_state": "TERMINATED",
                    "department": "Engineering",
                }
            ]
        },
        "roles": {"roles": []},
        "access_profiles": {"access_profiles": []},
        "entitlements": {"entitlements": []},
        "relationships": {"relationships": []},
    }
    r = CentralizedIdentityResolver(custom_sp_data)
    res = r.resolve_identity("Terminated Staff")
    assert res.status == IdentityResolutionStatus.RESOLVED
    assert res.lifecycle_category == IdentityLifecycleCategory.LEAVER

    sp_details = SailPointChangeDetails(
        identity_id="sp-ident-leaver-user",
        identity_name="Terminated Staff",
        requested_role="Developer Access",
        request_status="APPROVED",
        approval_status="APPROVED",
        provisioning_status="PROVISIONED",
    )
    record = ChangeRequestRecord(
        request_number="REQ-SP-LEAVER-01",
        title="Leaver Staff Request",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    temp_repo.create_change_request(record)
    runner = AssessmentRunnerService(temp_repo)
    runner.loader.load_sailpoint_governance = lambda: custom_sp_data
    ok, msg, result = runner.run_assessment(record.request_number)
    assert ok and result is not None

    assert result.baseline_report.deployment_verdict.value == "BLOCK_DEPLOYMENT"
    rule_ids = [g.rule_id for g in result.baseline_report.identified_security_gaps]
    assert "SP-05" in rule_ids


def test_duplicate_and_ambiguous_identity_resolution(temp_repo: ChangeRepository):
    """Verify duplicate/ambiguous identity matches trigger SP-CORR-02 WARN."""
    ambiguous_sp_data = {
        "identities": {
            "identities": [
                {"id": "sp-ident-alex-1", "display_name": "Alex Taylor", "email": "alex.t1@example.com"},
                {"id": "sp-ident-alex-2", "display_name": "Alex Taylor", "email": "alex.t2@example.com"},
            ]
        },
        "roles": {"roles": []},
        "access_profiles": {"access_profiles": []},
        "entitlements": {"entitlements": []},
        "relationships": {"relationships": []},
    }
    resolver = CentralizedIdentityResolver(ambiguous_sp_data)
    res = resolver.resolve_identity("Alex Taylor")
    assert res.status == IdentityResolutionStatus.AMBIGUOUS
    assert len(res.candidate_matches) == 2

    sp_details = SailPointChangeDetails(
        identity_name="Alex Taylor",
        requested_role="Developer Access",
    )
    record = ChangeRequestRecord(
        request_number="REQ-SP-AMBIGUOUS-01",
        title="Ambiguous User Request",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    temp_repo.create_change_request(record)
    runner = AssessmentRunnerService(temp_repo)
    runner.loader.load_sailpoint_governance = lambda: ambiguous_sp_data
    ok, msg, result = runner.run_assessment(record.request_number)
    assert ok and result is not None

    assert result.baseline_report.deployment_verdict.value == "WARN_MANUAL_REVIEW"
    rule_ids = [g.rule_id for g in result.baseline_report.identified_security_gaps]
    assert "SP-CORR-02" in rule_ids


def test_conflicting_employee_id_and_name_resolution(temp_repo: ChangeRepository):
    """Verify conflict between employee ID and target name triggers SP-CORR-03 BLOCK."""
    conflict_sp_data = {
        "identities": {
            "identities": [
                {"id": "sp-ident-emp-1", "display_name": "Alice Green", "employee_id": "EID-1001"},
                {"id": "sp-ident-emp-2", "display_name": "Bob Blue", "employee_id": "EID-1002"},
            ]
        },
        "roles": {"roles": []},
        "access_profiles": {"access_profiles": []},
        "entitlements": {"entitlements": []},
        "relationships": {"relationships": []},
    }
    resolver = CentralizedIdentityResolver(conflict_sp_data)
    # Query is Alice Green but Employee ID is EID-1002 (Bob Blue)
    res = resolver.resolve_identity(query="Alice Green", employee_id="EID-1002")
    assert res.status == IdentityResolutionStatus.CONFLICT
    assert "Identity Conflict Detected" in res.message


def test_governance_access_states_strictly_distinct():
    """Verify requested, approved, provisioned, and effective access remain strictly distinct."""
    # 1. Requested only (In-flight)
    s1 = CentralizedIdentityResolver.evaluate_access_state("SUBMITTED", "PENDING", "NOT_PROVISIONED")
    assert s1.is_requested is True
    assert s1.is_approved is False
    assert s1.is_provisioned is False
    assert s1.is_effective is False
    assert "PENDING_APPROVAL" in s1.governance_state_summary

    # 2. Approved but unprovisioned (SP-02 gap)
    s2 = CentralizedIdentityResolver.evaluate_access_state("APPROVED", "APPROVED", "PENDING_PROVISIONING")
    assert s2.is_approved is True
    assert s2.is_provisioned is False
    assert s2.is_effective is False
    assert "APPROVED_PENDING_PROVISIONING" in s2.governance_state_summary

    # 3. Provisioned without approval (Orphan grant)
    s3 = CentralizedIdentityResolver.evaluate_access_state("PENDING", "REJECTED", "PROVISIONED")
    assert s3.is_approved is False
    assert s3.is_provisioned is True
    assert s3.is_effective is False
    assert "PROVISIONED_WITHOUT_APPROVAL" in s3.governance_state_summary

    # 4. Effective access (Requires BOTH approval and provisioning)
    s4 = CentralizedIdentityResolver.evaluate_access_state("APPROVED", "APPROVED", "PROVISIONED")
    assert s4.is_approved is True
    assert s4.is_provisioned is True
    assert s4.is_effective is True
    assert "EFFECTIVE" in s4.governance_state_summary
