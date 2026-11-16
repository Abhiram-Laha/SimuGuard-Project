"""End-to-End and Unit Regression Tests for IAM Lifecycle Extraction and Governance in SimuGuard AI.

Validates:
1. Arjun Mehta Mover change request extraction, summary generation, and assessment.
2. Joiner, Mover, and Leaver lifecycle classification across varied enterprise labels.
3. Strict anti-substitution and centralized identity resolution.
4. Privileged entitlement detection (SAP Finance Administrator).
5. Dynamic configuration table rendering.
6. Multi-gap assessment triggers (SP-CORR-01, SP-01, SP-02, SP-04, SP-06).
"""

from pathlib import Path
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

from simuguard.identity import CentralizedIdentityResolver, IdentityResolutionStatus
from simuguard.models.enums import DeploymentVerdict
from storage.database import init_db
from storage.models import (
    ChangeDomain,
    ChangeRequestRecord,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService
from ui.services.servicenow_extractor import ServiceNowExtractor


@pytest.fixture
def temp_repo():
    """Create an isolated, temporary SQLite database and repository."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_arjun_mehta_minimal_mover_extraction_and_assessment(temp_repo: ChangeRepository):
    """Verify exact user-reported Arjun Mehta minimal snippet extraction and assessment."""
    pasted_text = """
Employee: Arjun Mehta
Employee ID: EMP-2871
Current department: Operations
New department: Finance
New role: Finance Operations Analyst
Remove: Operations-Standard, Warehouse-Reporting
Add: Finance-Standard, SAP Finance Display, SAP Finance Administrator
"""
    cfg = ServiceNowExtractor.extract_from_text(pasted_text)

    # 1. Extraction checks
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.lifecycle_type == "MOVER"
    assert "Arjun Mehta" in cfg.identity_name
    assert cfg.employee_id == "EMP-2871"
    assert cfg.current_department == "Operations"
    assert cfg.new_department == "Finance"
    assert cfg.requested_role == "Finance Operations Analyst"
    assert cfg.access_to_remove == ["Operations-Standard", "Warehouse-Reporting"]
    assert cfg.access_to_add == ["Finance-Standard", "SAP Finance Display", "SAP Finance Administrator"]
    assert cfg.privileged_access_requested is True
    assert "SAP Finance Administrator" in cfg.privileged_entitlements

    # 2. Plain-English summary checks
    summary = ServiceNowExtractor.generate_summary(cfg)
    assert "Arjun Mehta" in summary.what_is_requested
    assert "EMP-2871" in summary.what_is_requested
    assert "Operations" in summary.what_is_requested
    assert "Finance" in summary.what_is_requested
    assert "Finance Operations Analyst" in summary.what_is_requested
    assert "Operations-Standard" in summary.what_is_requested
    assert "SAP Finance Administrator" in summary.what_is_requested

    # 3. Key configuration table checks
    key_changes = summary.key_configuration_changes
    assert key_changes["Target Identity"] == "Arjun Mehta (EMP-2871)"
    assert key_changes["Employee ID"] == "EMP-2871"
    assert key_changes["Current Department"] == "Operations"
    assert key_changes["New Department"] == "Finance"
    assert key_changes["Department Transition"] == "Operations → Finance"
    assert key_changes["New Role"] == "Finance Operations Analyst"
    assert "Operations-Standard" in key_changes["Access to Remove"]
    assert "Warehouse-Reporting" in key_changes["Access to Remove"]
    assert "Finance-Standard" in key_changes["Access to Add"]
    assert "SAP Finance Administrator" in key_changes["Privileged Entitlements"]

    # 4. Initial observations checks
    obs_text = " ".join(summary.initial_observations)
    assert "SAP Finance Administrator" in obs_text
    assert "Privileged Entitlement" in obs_text
    assert "SoD" in obs_text or "Toxic Combination" in obs_text

    # 5. Pre-flight simulation assessment execution
    cfg.request_number = "CHG-TEST-ARJUN-01"
    sp_details = SailPointChangeDetails(
        identity_name=cfg.identity_name,
        employee_id=cfg.employee_id,
        current_department=cfg.current_department,
        new_department=cfg.new_department,
        current_role=cfg.current_role,
        new_role=cfg.new_role,
        requested_role=cfg.requested_role,
        access_to_add=cfg.access_to_add,
        access_to_remove=cfg.access_to_remove,
        entitlement=cfg.entitlement,
        privileged_access_requested=cfg.privileged_access_requested,
        privileged_entitlements=cfg.privileged_entitlements,
        lifecycle_type=cfg.lifecycle_type,
        approval_status=cfg.approval_status or "APPROVED",
        provisioning_status="UNPROVISIONED",
    )
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title="Mover - Arjun Mehta",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    temp_repo.create_change_request(rec)

    runner = AssessmentRunnerService(repository=temp_repo)
    ok, msg, asmt = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and asmt is not None
    rep = asmt.baseline_report
    assert rep.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    assert rep.overall_risk_score == 100

    gap_rules = [g.rule_id for g in rep.identified_security_gaps]
    assert "SP-CORR-01" in gap_rules  # Unmapped identity
    assert "SP-04" in gap_rules       # Privileged Access (SAP Finance Administrator)
    assert "SP-06" in gap_rules       # Privilege Creep (Transfer conflict)
    assert "SP-02" in gap_rules       # Unprovisioned state


def test_joiner_extraction_and_summary():
    """Verify Joiner lifecycle extraction, dates, and plain-English summary."""
    joiner_text = """
REQUEST: RITM-JOIN-001
Title: New Hire Onboarding - Finance Analyst
Company: Apex Global Technologies
Worker details:
Employee: Ananya Sharma
Employee ID: EMP-4910
Worker type: Full-time employee
Department: Finance
Role: Senior Financial Analyst
Corporate email: ananya.sharma@apex-global.example
Start date: 15-Jan-2027

Requested access:
- Microsoft 365 - Enterprise
- SAP Finance Display
- Oracle Financials

Business justification:
Standard onboarding access for newly hired senior financial analyst.
"""
    cfg = ServiceNowExtractor.extract_from_text(joiner_text)
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.lifecycle_type == "JOINER"
    assert "Ananya Sharma" in cfg.identity_name
    assert cfg.employee_id == "EMP-4910"
    assert cfg.corporate_email == "ananya.sharma@apex-global.example"
    assert cfg.start_date == "15-Jan-2027"
    assert "Microsoft 365 - Enterprise" in cfg.access_to_add
    assert "SAP Finance Display" in cfg.access_to_add

    summary = ServiceNowExtractor.generate_summary(cfg)
    assert "Joiner Lifecycle Request" in summary.what_is_requested
    assert "Ananya Sharma" in summary.what_is_requested
    assert "Finance" in summary.what_is_requested
    assert summary.key_configuration_changes["Lifecycle Event"] == "Joiner (New Hire Onboarding)"
    assert summary.key_configuration_changes["Start Date"] == "15-Jan-2027"


def test_leaver_extraction_and_summary():
    """Verify Leaver lifecycle extraction, deprovisioning lists, and offboarding summary."""
    leaver_text = """
REQUEST: RITM-LEAV-002
Title: Contractor engagement completion and access revocation
Name: David Miller
Worker ID: CTR-5521
Worker type: External contractor
Department: Cloud Architecture
Termination date: 31-Dec-2026

Requested action:
Revoke access associated with the contractor identity, including:
- AWS Production - PowerUser
- ServiceNow - ITIL
- VPN remote access

Business justification:
Contract project concluded. Immediate access deprovisioning required.
"""
    cfg = ServiceNowExtractor.extract_from_text(leaver_text)
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.lifecycle_type == "LEAVER"
    assert "David Miller" in cfg.identity_name
    assert cfg.employee_id == "CTR-5521"
    assert cfg.termination_date == "31-Dec-2026"
    assert "AWS Production - PowerUser" in cfg.access_to_remove
    assert "VPN remote access" in cfg.access_to_remove

    summary = ServiceNowExtractor.generate_summary(cfg)
    assert "Leaver Lifecycle Request" in summary.what_is_requested
    assert "David Miller" in summary.what_is_requested
    assert summary.key_configuration_changes["Lifecycle Event"] == "Leaver (Personnel Offboarding / Revocation)"
    assert "AWS Production - PowerUser" in summary.key_configuration_changes["Access to Remove"]


def test_varied_labels_and_case_variations():
    """Verify extractor robustness against varied enterprise field names and casing."""
    varied_text = """
USER: John Doe
EMP ID: EMP-1234
USER EMAIL: john.doe@apex-global.example
FROM DEPARTMENT: Logistics
TO DEPARTMENT: Supply Chain
CURRENT JOB TITLE: Inventory Clerk
NEW JOB TITLE: Supply Chain Lead
REVOKE: Logistics-Basic, Scanner-App
GRANT: SupplyChain-Standard, SAP-Logistics-Admin
CHANGE DATE: 10-Jan-2027
"""
    cfg = ServiceNowExtractor.extract_from_text(varied_text)
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.lifecycle_type == "MOVER"
    assert "John Doe" in cfg.identity_name
    assert cfg.employee_id == "EMP-1234"
    assert cfg.current_department == "Logistics"
    assert cfg.new_department == "Supply Chain"
    assert cfg.requested_role == "Supply Chain Lead"
    assert cfg.access_to_remove == ["Logistics-Basic", "Scanner-App"]
    assert cfg.access_to_add == ["SupplyChain-Standard", "SAP-Logistics-Admin"]
    assert cfg.privileged_access_requested is True


def test_centralized_identity_resolver_strict_anti_substitution():
    """Verify exact worker ID resolution and strict refusal to guess/substitute unmapped IDs."""
    from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
    sp_data = EnterpriseDatasetLoader().load_sailpoint_governance()
    resolver = CentralizedIdentityResolver(sp_data)

    # 1. Unmapped explicit Employee ID: Must return UNMAPPED, never substitute another identity
    res_unmapped = resolver.resolve_identity(
        query="Arjun Mehta",
        employee_id="EMP-2871",
    )
    assert res_unmapped.status == IdentityResolutionStatus.UNMAPPED
    assert res_unmapped.identity is None
    assert "EMP-2871" in res_unmapped.message
    assert "strictly prohibited" in res_unmapped.message.lower()

    # 2. Secondary email resolution for real identity
    res_email = resolver.resolve_identity(
        email="sarah.chen@apex-global.example",
    )
    assert res_email.status == IdentityResolutionStatus.RESOLVED
    assert res_email.identity_id == "sp-ident-sarah-chen"

    # 3. Conflict detection between employee ID and mismatched email
    res_conflict = resolver.resolve_identity(
        employee_id="sp-ident-sarah-chen",
        email="marcus.vance@apex-global.example",
    )
    assert res_conflict.status in [IdentityResolutionStatus.CONFLICT, IdentityResolutionStatus.IDENTITY_MISMATCH]


def test_workspace_ui_renders_iam_mover_cleanly():
    """Verify Streamlit workspace renders IAM mover ticket without UI exceptions."""
    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    app.run()

    mover_text = """
Employee: Arjun Mehta
Employee ID: EMP-2871
Current department: Operations
New department: Finance
New role: Finance Operations Analyst
Remove: Operations-Standard, Warehouse-Reporting
Add: Finance-Standard, SAP Finance Display, SAP Finance Administrator
"""
    app.session_state["servicenow_raw_text"] = mover_text
    app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(mover_text)
    app.run()

    assert not app.exception
    cfg = app.session_state["extracted_config"]
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.lifecycle_type == "MOVER"
    assert "Arjun Mehta" in cfg.identity_name
    assert cfg.privileged_access_requested is True
