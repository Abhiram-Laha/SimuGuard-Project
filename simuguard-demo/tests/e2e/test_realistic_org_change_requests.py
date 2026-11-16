"""End-to-End Functional & Regression Tests for Realistic Enterprise Change Requests.

Tests all six synthetic enterprise change tickets:
1. 01_FW_Approved_SaaS_Integration (CHG0098421)
2. 02_FW_Overbroad_ThirdParty_Access (CHG0098476)
3. 03_FW_Production_Database_Rule_Incomplete (CHG0098510)
4. 04_IAM_Joiner_Standard_Finance_Analyst (RITM0047312)
5. 05_IAM_Mover_Conflicting_And_Privileged_Access (RITM0047398)
6. 06_IAM_Leaver_Contractor_Offboarding (RITM0047455)
"""

from pathlib import Path
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.identity import CentralizedIdentityResolver, IdentityResolutionStatus
from simuguard.models.enums import DeploymentVerdict, Severity
from storage.database import init_db
from storage.models import (
    ChangeDomain,
    ChangeRequestRecord,
    FirewallChangeDetails,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService
from ui.services.servicenow_extractor import ServiceNowExtractor

FOLDER = Path(__file__).resolve().parent.parent.parent.parent / "SimuGuard_Realistic_Org_Change_Requests"


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


def _read_scenario_file(filename: str) -> str:
    path = FOLDER / filename
    if not path.exists():
        # Fallback local search
        path = Path("SimuGuard_Realistic_Org_Change_Requests") / filename
    assert path.exists(), f"Scenario file not found: {path}"
    return path.read_text(encoding="utf-8")


# =============================================================================
# 1. FILE INGESTION & DETECTION
# =============================================================================

def test_all_six_realistic_scenario_files_exist_and_readable():
    """Verify all six realistic enterprise change request files are detected and readable."""
    expected_files = [
        "01_FW_Approved_SaaS_Integration.txt",
        "02_FW_Overbroad_ThirdParty_Access.txt",
        "03_FW_Production_Database_Rule_Incomplete.txt",
        "04_IAM_Joiner_Standard_Finance_Analyst.txt",
        "05_IAM_Mover_Conflicting_And_Privileged_Access.txt",
        "06_IAM_Leaver_Contractor_Offboarding.txt",
    ]
    for fn in expected_files:
        content = _read_scenario_file(fn)
        assert len(content.strip()) > 100, f"Scenario file {fn} is empty or unreadable."


# =============================================================================
# 2. FIREWALL SCENARIOS
# =============================================================================

def test_01_fw_approved_saas_integration_extraction_and_assessment(temp_repo: ChangeRepository):
    """Test 01: Scoped SaaS Integration (CHG0098421) extraction and pre-flight evaluation."""
    text = _read_scenario_file("01_FW_Approved_SaaS_Integration.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    # Extraction verification
    assert cfg.request_number == "CHG0098421"
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.priority == "MEDIUM"
    assert cfg.rule_name == "FIN-APP-TO-ACMEPAY"
    assert cfg.source_zone == "DC-APP"
    assert cfg.source_addresses == "10.24.16.0/27"
    assert cfg.destination_zone == "INTERNET"
    assert cfg.destination_addresses == "198.51.100.40/32"
    assert cfg.applications == "ssl"
    assert cfg.services == "tcp/443"
    assert cfg.destination_port == "443"
    assert "strict" in cfg.security_profile.lower()
    assert "enabled" in cfg.logging.lower()
    assert cfg.approval_status == "PENDING"
    assert cfg.approvals.get("Change manager") == "Pending"

    # Assessment execution
    repo = temp_repo
    runner = AssessmentRunnerService(repository=repo)
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        raw_content=cfg.raw_hcl,
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    ok, msg, res = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and res is not None
    rep = res.baseline_report
    # Manual review required because DC-APP is unmapped in topology and change manager is pending
    assert rep.deployment_verdict == DeploymentVerdict.WARN_MANUAL_REVIEW
    assert rep.overall_risk_score < 40
    assert any("DC-APP" in g.gap_title for g in rep.identified_security_gaps)


def test_02_fw_overbroad_third_party_access_blocked(temp_repo: ChangeRepository):
    """Test 02: Overbroad vendor access (CHG0098476) must be BLOCKED with high risk score."""
    text = _read_scenario_file("02_FW_Overbroad_ThirdParty_Access.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    assert cfg.request_number == "CHG0098476"
    assert cfg.priority == "HIGH"
    assert cfg.applications == "any"
    assert cfg.services == "any"
    assert cfg.security_profile.lower() == "none"
    assert "disabled" in cfg.logging.lower()
    assert cfg.approval_status == "PENDING"
    assert len(cfg.warnings) >= 3

    repo = temp_repo
    runner = AssessmentRunnerService(repository=repo)
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        raw_content=cfg.raw_hcl,
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    ok, msg, res = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and res is not None
    rep = res.baseline_report
    assert rep.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    assert rep.overall_risk_score >= 70
    gap_rules = [g.rule_id for g in rep.identified_security_gaps]
    assert "FW-01" in gap_rules  # PAN-OS App-ID Bypass


def test_03_fw_production_database_rule_incomplete(temp_repo: ChangeRepository):
    """Test 03: Incomplete database connectivity (CHG0098510) must flag TBD placeholder addresses."""
    text = _read_scenario_file("03_FW_Production_Database_Rule_Incomplete.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    assert cfg.request_number == "CHG0098510"
    assert any("tbd" in mf.lower() for mf in cfg.missing_fields)
    assert any("INCOMPLETE" in w for w in cfg.warnings)
    assert cfg.approval_status == "PENDING"

    repo = temp_repo
    runner = AssessmentRunnerService(repository=repo)
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        raw_content=cfg.raw_hcl,
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    ok, msg, res = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and res is not None
    rep = res.baseline_report
    # Must not be ALLOW with 0 score; must be blocked or manual review
    assert rep.deployment_verdict in (DeploymentVerdict.BLOCK_DEPLOYMENT, DeploymentVerdict.WARN_MANUAL_REVIEW)
    assert any(g.rule_id == "INCOMPLETE-01" for g in rep.identified_security_gaps)


# =============================================================================
# 3. IAM SCENARIOS & IDENTITY RESOLUTION
# =============================================================================

def test_04_iam_joiner_standard_finance_analyst(temp_repo: ChangeRepository):
    """Test 04: Joiner (RITM0047312) Priya Nair (EMP-4102) resolution and unapproved in-flight check."""
    text = _read_scenario_file("04_IAM_Joiner_Standard_Finance_Analyst.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    assert cfg.request_number == "RITM0047312"
    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert cfg.subcategory == "Joiner Access Request"
    assert cfg.priority == "LOW"
    assert "Priya Nair" in cfg.identity_name
    assert cfg.employee_id == "EMP-4102"
    assert "Microsoft 365" in cfg.entitlement
    assert cfg.approval_status == "PENDING"

    # Strictly test identity resolution: MUST NOT substitute Priya Patel!
    sp_data = EnterpriseDatasetLoader().load_sailpoint_governance()
    resolver = CentralizedIdentityResolver(sp_data)
    res = resolver.resolve_identity(query=cfg.identity_name, employee_id=cfg.employee_id)
    assert res.status == IdentityResolutionStatus.UNMAPPED
    assert res.identity is None
    assert "EMP-4102" in res.message
    assert "prohibited" in res.message.lower()

    # Pre-flight assessment
    repo = temp_repo
    sp_details = SailPointChangeDetails(
        identity_name=cfg.identity_name,
        requested_role=cfg.requested_role,
        entitlement=cfg.entitlement,
        approval_status=cfg.approval_status,
        provisioning_status="UNPROVISIONED",
    )
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    runner = AssessmentRunnerService(repository=repo)
    ok, msg, asmt = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and asmt is not None
    rep = asmt.baseline_report
    assert rep.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    gaps = [g.rule_id for g in rep.identified_security_gaps]
    assert "SP-CORR-01" in gaps  # Unmapped identity
    assert "SP-01" in gaps       # In-flight unapproved


def test_05_iam_mover_conflicting_and_privileged_access(temp_repo: ChangeRepository):
    """Test 05: Mover (RITM0047398) Arjun Mehta (EMP-2871) privileged SAP access & privilege creep."""
    text = _read_scenario_file("05_IAM_Mover_Conflicting_And_Privileged_Access.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    assert cfg.request_number == "RITM0047398"
    assert cfg.subcategory == "Mover Access Modification"
    assert "Arjun Mehta" in cfg.identity_name
    assert cfg.employee_id == "EMP-2871"
    assert "SAP - Finance Administrator" in cfg.entitlement
    assert cfg.privileged_access_requested is True

    repo = temp_repo
    sp_details = SailPointChangeDetails(
        identity_name=cfg.identity_name,
        requested_role=cfg.requested_role,
        entitlement=cfg.entitlement,
        approval_status=cfg.approval_status,
        provisioning_status="UNPROVISIONED",
    )
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    runner = AssessmentRunnerService(repository=repo)
    ok, msg, asmt = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and asmt is not None
    rep = asmt.baseline_report
    assert rep.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    assert rep.overall_risk_score == 100
    gaps = [g.rule_id for g in rep.identified_security_gaps]
    assert "SP-04" in gaps       # Privileged Access Violation
    assert "SP-06" in gaps       # Privilege Creep
    assert "SP-01" in gaps       # In-Flight Unapproved


def test_06_iam_leaver_contractor_offboarding(temp_repo: ChangeRepository):
    """Test 06: Leaver (RITM0047455) Vikram Rao (CTR-0924) contractor offboarding and revocation."""
    text = _read_scenario_file("06_IAM_Leaver_Contractor_Offboarding.txt")
    cfg = ServiceNowExtractor.extract_from_text(text)

    assert cfg.request_number == "RITM0047455"
    assert cfg.subcategory == "Leaver Access Revocation"
    assert "Vikram Rao" in cfg.identity_name
    assert cfg.employee_id == "CTR-0924"
    assert "contractor" in cfg.worker_type.lower()
    assert any("reconciliation" in w.lower() for w in cfg.warnings)

    # Strictly test identity resolution: MUST NOT substitute Vikram Sharma (an internal employee)!
    sp_data = EnterpriseDatasetLoader().load_sailpoint_governance()
    resolver = CentralizedIdentityResolver(sp_data)
    res = resolver.resolve_identity(query=cfg.identity_name, worker_id=cfg.employee_id)
    assert res.status == IdentityResolutionStatus.UNMAPPED
    assert res.identity is None

    repo = temp_repo
    sp_details = SailPointChangeDetails(
        identity_name=cfg.identity_name,
        requested_role=cfg.requested_role,
        entitlement=cfg.entitlement,
        approval_status=cfg.approval_status,
        provisioning_status="UNPROVISIONED",
    )
    rec = ChangeRequestRecord(
        request_number=cfg.request_number,
        title=cfg.title,
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        priority=cfg.priority,
        status=WorkflowState.SUBMITTED.value,
        category=cfg.category,
        subcategory=cfg.subcategory,
        sailpoint_details_json=sp_details.model_dump_json(),
    )
    if repo.get_change_request(cfg.request_number):
        repo.update_change_request(rec)
    else:
        repo.create_change_request(rec)

    runner = AssessmentRunnerService(repository=repo)
    ok, msg, asmt = runner.run_assessment(cfg.request_number, force_reassessment=True)
    assert ok and asmt is not None
    rep = asmt.baseline_report
    assert rep.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
    gaps = [g.rule_id for g in rep.identified_security_gaps]
    assert "SP-CORR-01" in gaps
    assert "SP-01" in gaps
    # Validation plan must include downstream systems verification
    assert any("Downstream" in v.target_component or "accounts" in v.cli_command for v in rep.pre_implementation_validation_plan)


# =============================================================================
# 4. CROSS-REQUEST ISOLATION & DATA INTEGRITY
# =============================================================================

def test_cross_request_session_isolation_in_workspace():
    """Verify loading different realistic tickets resets widget state and prevents data bleed."""
    app = AppTest.from_file("simuguard-demo/app.py", default_timeout=30)
    app.run()

    # Load ticket 1
    t1 = _read_scenario_file("01_FW_Approved_SaaS_Integration.txt")
    app.session_state["servicenow_raw_text"] = t1
    app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(t1)
    app.run()
    assert not app.exception
    assert app.session_state["extracted_config"].request_number == "CHG0098421"

    # Load ticket 4 (IAM)
    t4 = _read_scenario_file("04_IAM_Joiner_Standard_Finance_Analyst.txt")
    app.session_state["servicenow_raw_text"] = t4
    app.session_state["extracted_config"] = ServiceNowExtractor.extract_from_text(t4)
    app.run()
    assert not app.exception
    assert app.session_state["extracted_config"].request_number == "RITM0047312"
    assert app.session_state["extracted_config"].domain == "IDENTITY_GOVERNANCE"
    # Ensure no leftover rule name from ticket 1
    assert app.session_state["extracted_config"].rule_name == ""
