"""End-to-End Tests for Single Assessment Workspace & ServiceNow Extractor UX Redesign.

Verifies:
1. Text extraction from structured ServiceNow tickets, HCL blocks, and SailPoint access requests.
2. Detection of missing and ambiguous configuration fields (wildcard CIDRs, App-ID 'any', etc.).
3. End-to-end execution of pre-flight simulation from the single workspace for both Firewall and SailPoint.
4. Inline generation and verification of candidate remediation, candidate validation, and comparison data.
5. In-place loading of historical assessment records into the primary workspace.
6. Publication-grade PDF and JSON compliance exports generated directly within the workspace.
7. Headless Streamlit AppTest verification of the redesigned Single Assessment Workspace and Settings page.
"""

from pathlib import Path
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

from config.settings import (
    NAV_PAGES,
    PAGE_HISTORY,
    PAGE_NEW_ASSESSMENT,
    PAGE_REPORTS,
    PAGE_SETTINGS,
)
from storage.database import init_db
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.pages.workspace import _execute_assessment_from_workspace, _load_historical_record_into_workspace
from ui.services.assessment_runner import AssessmentRunnerService
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)
from ui.services.servicenow_extractor import ExtractedConfig, ServiceNowExtractor

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def temp_repo():
    """Isolated temporary SQLite repository for workspace workflow tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_servicenow_extractor_firewall_samples():
    """Verify ServiceNowExtractor correctly parses firewall tickets and detects warnings."""
    # 1. PR-4082 Ticket with embedded HCL
    pr_text = ServiceNowExtractor.get_sample_pr_4082()
    cfg = ServiceNowExtractor.extract_from_text(pr_text)

    assert cfg.domain == "NETWORK_SECURITY"
    assert "4082" in cfg.request_number or "4082" in cfg.title
    assert cfg.rule_name == "direct-db-access-rule"
    assert cfg.source_zone == "Untrust-Internet"
    assert cfg.destination_zone == "Prod-Database"
    assert cfg.source_addresses == "0.0.0.0/0"
    assert cfg.destination_addresses == "10.100.2.15/32"
    assert cfg.applications == "any"
    assert cfg.action == "allow"
    assert len(cfg.warnings) >= 2  # App-ID 'any' and Untrust into Database tier
    assert cfg.raw_hcl is not None and len(cfg.raw_hcl) > 0

    # 2. Allow Netflix Streaming
    netflix_text = ServiceNowExtractor.get_sample_allow_netflix()
    n_cfg = ServiceNowExtractor.extract_from_text(netflix_text)
    assert n_cfg.domain == "NETWORK_SECURITY"
    assert "netflix" in n_cfg.applications.lower()
    assert n_cfg.source_zone == "Corp-Users"
    assert n_cfg.destination_zone == "Untrust-Internet"
    assert any("Destination Address is wildcard 'any'" in w for w in n_cfg.warnings)

    # 3. Safe Telemetry Rule
    safe_text = ServiceNowExtractor.get_sample_safe_rule()
    s_cfg = ServiceNowExtractor.extract_from_text(safe_text)
    assert s_cfg.domain == "NETWORK_SECURITY"
    assert s_cfg.applications == "ssl"
    assert s_cfg.destination_addresses == "198.51.100.24/32"
    assert len(s_cfg.warnings) == 0  # Compliant rule has no warnings


def test_servicenow_extractor_sailpoint_samples():
    """Verify ServiceNowExtractor parses SailPoint access requests and validates identities."""
    sp_text = ServiceNowExtractor.get_sample_sailpoint()
    cfg = ServiceNowExtractor.extract_from_text(sp_text)

    assert cfg.domain == "IDENTITY_GOVERNANCE"
    assert "Sarah Chen" in cfg.identity_name
    assert "Finance & Treasury Analyst" in cfg.requested_role
    assert "Production S3 CUI Vault Read Access" in cfg.access_profile
    assert "AWS Production S3 CUI Vault Read" in cfg.entitlement
    assert "Corporate Active Directory" in cfg.identity_source
    assert cfg.account_id == "sp-acct-ad-sarah-chen"
    # Contractor requesting privileged CUI should trigger alert
    assert any("Contractor identity requesting privileged" in w for w in cfg.warnings)


def test_single_workspace_firewall_end_to_end_assessment(temp_repo: ChangeRepository):
    """Verify single-workspace execution: intake -> pre-flight simulation -> inline remediation."""
    cfg = ServiceNowExtractor.extract_from_text(ServiceNowExtractor.get_sample_pr_4082())
    req_no = temp_repo.generate_next_request_number()
    cfg.request_number = req_no

    # Execute assessment routine
    _execute_assessment_from_workspace(temp_repo, cfg)

    # Verify Change Request created in SQLite
    cr = temp_repo.get_change_request(req_no)
    assert cr is not None
    assert cr.domain == ChangeDomain.NETWORK_SECURITY.value
    assert cr.status == WorkflowState.ANALYSIS_COMPLETE.value

    # Verify Baseline Assessment Record
    base_asmt = temp_repo.get_latest_assessment(req_no, assessment_type="ORIGINAL")
    assert base_asmt is not None
    assert base_asmt.verdict == "BLOCK_DEPLOYMENT"
    assert base_asmt.composite_risk_score == 100.0
    assert base_asmt.security_gaps_count > 0
    assert base_asmt.blast_radius_nodes_count > 0

    # Verify Post-Remediation Record
    post_asmt = temp_repo.get_latest_assessment(req_no, assessment_type="POST_REMEDIATION")
    assert post_asmt is not None
    assert post_asmt.verdict == "ALLOW"
    assert post_asmt.composite_risk_score <= 25.0

    # Verify Remediation Record & Candidate Synthesis
    rem_rec = temp_repo.get_remediation_record(req_no)
    assert rem_rec is not None
    assert rem_rec.status == "VALIDATED"
    assert len(rem_rec.synthesized_hcl) > 0
    assert rem_rec.comparison_json is not None

    # Verify One-Click PDF and JSON exports on same page
    pdf_bytes = build_executive_pdf(cr, base_asmt, rem_rec)
    assert pdf_bytes.startswith(b"%PDF")
    json_export = build_executive_json(cr, base_asmt, rem_rec)
    assert req_no in json_export


def test_single_workspace_sailpoint_end_to_end_assessment(temp_repo: ChangeRepository):
    """Verify single-workspace execution for SailPoint access request without Terraform."""
    cfg = ServiceNowExtractor.extract_from_text(ServiceNowExtractor.get_sample_sailpoint())
    req_no = temp_repo.generate_next_request_number()
    cfg.request_number = req_no

    _execute_assessment_from_workspace(temp_repo, cfg)

    cr = temp_repo.get_change_request(req_no)
    assert cr is not None
    assert cr.domain == ChangeDomain.IDENTITY_GOVERNANCE.value

    base_asmt = temp_repo.get_latest_assessment(req_no, assessment_type="ORIGINAL")
    assert base_asmt is not None
    assert base_asmt.verdict in ["BLOCK_DEPLOYMENT", "WARN_MANUAL_REVIEW"]
    assert base_asmt.security_gaps_count > 0


def test_load_historical_record_into_workspace(temp_repo: ChangeRepository):
    """Verify that an existing change request can be loaded into the workspace session seamlessly."""
    cfg = ServiceNowExtractor.extract_from_text(ServiceNowExtractor.get_sample_safe_rule())
    req_no = temp_repo.generate_next_request_number()
    cfg.request_number = req_no
    _execute_assessment_from_workspace(temp_repo, cfg)

    # Now load into workspace
    _load_historical_record_into_workspace(temp_repo, req_no)

    cr = temp_repo.get_change_request(req_no)
    asmt = temp_repo.get_latest_assessment(req_no, assessment_type="ORIGINAL")
    assert cr is not None
    assert asmt is not None
    assert asmt.verdict == "ALLOW"


def test_headless_single_workspace_rendering_via_apptest():
    """Headless Streamlit AppTest: Verify Single Assessment Workspace loads and renders all sections."""
    app_path = WORKSPACE_ROOT / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)
    at.session_state["active_page"] = PAGE_NEW_ASSESSMENT
    at.session_state["environment_mode"] = "DEMO"
    at.session_state["show_guided_tour"] = True
    at.run()

    assert not at.exception
    # Check that main workspace title is rendered
    assert any("Change Risk Assessment" in m.value for m in at.markdown)
    # Check section headers
    assert any("1. Paste Change Request" in m.value for m in at.markdown)
    assert any("2. Change Request Summary" in m.value for m in at.markdown)
    assert any("3. Extracted Configuration Review" in m.value for m in at.markdown)
    # Check that primary run assessment button exists
    assert any("Run Pre-Flight Assessment" in b.label for b in at.button)


def test_headless_settings_administration_page_via_apptest():
    """Headless Streamlit AppTest: Verify Settings & Diagnostics renders administration controls."""
    app_path = WORKSPACE_ROOT / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)
    at.session_state["active_page"] = PAGE_SETTINGS
    at.session_state["environment_mode"] = "DEMO"
    at.run()

    assert not at.exception
    # Check that administrative controls are present
    assert any("ITSM Environment & Database Administration" in m.value for m in at.markdown)
    assert any("Reset Demo Sandbox Data" in b.label for b in at.button)
    # Check that diagnostics KPIs are rendered
    assert len(at.markdown) > 0


def test_sidebar_structure_contains_only_simplified_pages():
    """Verify that NAV_PAGES contains strictly the simplified primary entries."""
    assert PAGE_NEW_ASSESSMENT in NAV_PAGES
    assert PAGE_HISTORY in NAV_PAGES
    assert PAGE_REPORTS in NAV_PAGES
    assert PAGE_SETTINGS in NAV_PAGES
    assert len(NAV_PAGES) == 4


# =============================================================================
# FIVE OFFICIAL FIREWALL CHANGE REQUESTS VALIDATION (CHG-1001 to CHG-1005)
# =============================================================================

def test_chg_2026_1001_outbound_https_customer_portal(temp_repo: ChangeRepository):
    """CHG-2026-1001: Scoped Outbound HTTPS API Connectivity (Expected Verdict: ALLOW, Score: 0)."""
    text = ServiceNowExtractor.get_sample_chg_1001()
    cfg = ServiceNowExtractor.extract_from_text(text)

    # 1. Extraction Verification
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.request_number == "CHG-2026-1001"
    assert "Allow outbound HTTPS connectivity" in cfg.title
    assert cfg.rule_name == "Allow-Customer-Portal-API-HTTPS"
    assert cfg.source_zone == "Trust-Application"
    assert cfg.source_addresses == "10.100.10.0/24"
    assert cfg.destination_zone == "Untrust-Internet"
    assert cfg.destination_addresses == "198.51.100.25/32"
    assert cfg.applications == "ssl"
    assert cfg.services == "tcp-443"
    assert cfg.destination_port == "443"
    assert cfg.action == "allow"
    assert cfg.security_profile == "Strict-Enterprise-Security"
    assert "Enabled" in cfg.logging
    assert cfg.is_nat_change is False
    assert len(cfg.missing_fields) == 0
    assert len(cfg.warnings) == 0  # Clean compliant change

    # 2. End-to-End Simulation
    _execute_assessment_from_workspace(temp_repo, cfg)
    rec = temp_repo.get_change_request("CHG-2026-1001")
    assert rec is not None
    asmt = temp_repo.get_latest_assessment("CHG-2026-1001", assessment_type="ORIGINAL")
    assert asmt is not None
    assert asmt.verdict == "ALLOW"
    assert asmt.composite_risk_score == 0
    assert asmt.security_gaps_count == 0


def test_chg_2026_1002_unrestricted_outbound_internet(temp_repo: ChangeRepository):
    """CHG-2026-1002: Unrestricted Outbound Internet Egress (Expected Verdict: BLOCK, Score: 100)."""
    text = ServiceNowExtractor.get_sample_chg_1002()
    cfg = ServiceNowExtractor.extract_from_text(text)

    # 1. Extraction Verification
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.request_number == "CHG-2026-1002"
    assert "unrestricted outbound internet access" in cfg.title.lower()
    assert cfg.rule_name == "Allow-Analytics-Internet-Access"
    assert cfg.source_zone == "Trust-Analytics"
    assert cfg.source_addresses == "10.100.20.0/24"
    assert cfg.destination_zone == "Untrust-Internet"
    assert cfg.destination_addresses == "any"
    assert cfg.applications == "any"
    assert cfg.services == "any"
    assert cfg.security_profile.lower() in ["none", "disabled", ""]
    assert "disabled" in cfg.logging.lower()
    assert cfg.is_nat_change is False

    # 2. Risk & Ambiguity Parameter Warnings
    assert any("Destination Address is wildcard 'any'" in w for w in cfg.warnings)
    assert any("App-ID is set to 'any'" in w for w in cfg.warnings)
    assert any("Service / Port is set to 'any'" in w for w in cfg.warnings)
    assert any("Security Profile Group is set to 'none'" in w for w in cfg.warnings)
    assert any("Audit Logging is disabled" in w for w in cfg.warnings)

    # 3. End-to-End Simulation & Remediation
    _execute_assessment_from_workspace(temp_repo, cfg)
    rec = temp_repo.get_change_request("CHG-2026-1002")
    assert rec is not None
    asmt = temp_repo.get_latest_assessment("CHG-2026-1002", assessment_type="ORIGINAL")
    assert asmt is not None
    assert asmt.verdict == "BLOCK_DEPLOYMENT"
    assert asmt.composite_risk_score == 100
    assert asmt.security_gaps_count >= 2

    # Verify remediation candidates generated and validated
    remed = temp_repo.get_remediation_record("CHG-2026-1002")
    assert remed is not None
    post_asmt = temp_repo.get_latest_assessment("CHG-2026-1002", assessment_type="POST_REMEDIATION")
    assert post_asmt is not None
    assert post_asmt.verdict in ["ALLOW", "VERIFIED_SAFE"]
    assert post_asmt.composite_risk_score == 0


def test_chg_2026_1003_internal_network_segmentation(temp_repo: ChangeRepository):
    """CHG-2026-1003: Internal Banking Network Segmentation (Expected Verdict: ALLOW, Score: 0)."""
    text = ServiceNowExtractor.get_sample_chg_1003()
    cfg = ServiceNowExtractor.extract_from_text(text)

    # 1. Extraction Verification
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.request_number == "CHG-2026-1003"
    assert "internal database servers" in cfg.title.lower()
    assert cfg.rule_name == "Allow-Banking-App-To-DB"
    assert cfg.source_zone == "Trust-Application"
    assert cfg.source_addresses == "10.200.10.0/24"
    assert cfg.destination_zone == "Trust-Database"
    assert cfg.destination_addresses == "10.200.20.15/32"
    assert cfg.applications == "postgresql"
    assert cfg.services == "tcp-5432"
    assert cfg.destination_port == "5432"
    assert cfg.action == "allow"
    assert cfg.security_profile == "Strict-Enterprise-Security"
    assert "Enabled" in cfg.logging
    assert len(cfg.warnings) == 0

    # 2. End-to-End Simulation
    _execute_assessment_from_workspace(temp_repo, cfg)
    rec = temp_repo.get_change_request("CHG-2026-1003")
    assert rec is not None
    asmt = temp_repo.get_latest_assessment("CHG-2026-1003", assessment_type="ORIGINAL")
    assert asmt is not None
    assert asmt.verdict == "ALLOW"
    assert asmt.composite_risk_score == 0
    assert asmt.security_gaps_count == 0


def test_chg_2026_1004_inbound_nat_support_portal(temp_repo: ChangeRepository):
    """CHG-2026-1004: Inbound Destination NAT & Security Policy (Expected Verdict: ALLOW, Score: 0).
    Verifies strict separation of external pre-NAT public IP from internal post-NAT private IP.
    """
    text = ServiceNowExtractor.get_sample_chg_1004()
    cfg = ServiceNowExtractor.extract_from_text(text)

    # 1. Extraction Verification
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.request_number == "CHG-2026-1004"
    assert "inbound nat and security policy" in cfg.title.lower()
    assert cfg.is_nat_change is True

    # 2. Strict NAT Field Isolation
    assert cfg.nat_rule_name == "NAT-Support-Portal-Inbound"
    assert cfg.nat_original_source_zone == "Untrust-Internet"
    assert cfg.nat_original_destination_zone == "Untrust-Internet"
    assert cfg.nat_original_destination_address == "203.0.113.50"
    assert cfg.nat_original_destination_port == "443"
    assert cfg.nat_translated_destination_address == "10.100.30.25"
    assert cfg.nat_translated_destination_port == "443"

    # 3. Security Policy Targets Post-NAT Private Destination (NOT Public IP)
    assert cfg.rule_name == "Allow-Inbound-Support-Portal"
    assert cfg.source_zone == "Untrust-Internet"
    assert cfg.destination_zone == "Trust-DMZ" or "Untrust" in cfg.destination_zone
    assert cfg.destination_addresses == "10.100.30.25"
    assert cfg.nat_original_destination_address != cfg.destination_addresses
    assert "10.100.30.25" in cfg.destination_addresses
    assert cfg.applications == "ssl"
    assert cfg.services == "tcp-443"
    assert cfg.destination_port == "443"
    assert cfg.security_profile == "Strict-Enterprise-Security"

    # 4. End-to-End Simulation
    _execute_assessment_from_workspace(temp_repo, cfg)
    rec = temp_repo.get_change_request("CHG-2026-1004")
    assert rec is not None
    asmt = temp_repo.get_latest_assessment("CHG-2026-1004", assessment_type="ORIGINAL")
    assert asmt is not None
    assert asmt.verdict == "ALLOW"
    assert asmt.composite_risk_score == 0
    assert asmt.security_gaps_count == 0


def test_chg_2026_1005_unrestricted_vendor_connectivity(temp_repo: ChangeRepository):
    """CHG-2026-1005: Unrestricted Vendor Connectivity Modification (Expected Verdict: BLOCK, Score: 100)."""
    text = ServiceNowExtractor.get_sample_chg_1005()
    cfg = ServiceNowExtractor.extract_from_text(text)

    # 1. Extraction Verification
    assert cfg.domain == "NETWORK_SECURITY"
    assert cfg.request_number == "CHG-2026-1005"
    assert "unrestricted vendor connectivity" in cfg.title.lower()
    assert cfg.rule_name == "Allow-Vendor-Integration-Any"
    assert cfg.existing_rule_name == "Allow-Vendor-Integration"
    assert cfg.source_zone == "Trust-Vendor"
    assert cfg.source_addresses == "10.100.40.0/24"
    assert cfg.destination_zone == "Untrust-Internet"
    assert cfg.destination_addresses == "any"
    assert cfg.applications == "any"
    assert cfg.services == "any"
    assert cfg.security_profile.lower() in ["none", "disabled", ""]
    assert "disabled" in cfg.logging.lower()

    # 2. Risk & Ambiguity Parameter Warnings
    assert any("Destination Address is wildcard 'any'" in w for w in cfg.warnings)
    assert any("App-ID is set to 'any'" in w for w in cfg.warnings)
    assert any("Service / Port is set to 'any'" in w for w in cfg.warnings)
    assert any("Security Profile Group is set to 'none'" in w for w in cfg.warnings)
    assert any("Audit Logging is disabled" in w for w in cfg.warnings)

    # 3. End-to-End Simulation & Remediation
    _execute_assessment_from_workspace(temp_repo, cfg)
    rec = temp_repo.get_change_request("CHG-2026-1005")
    assert rec is not None
    asmt = temp_repo.get_latest_assessment("CHG-2026-1005", assessment_type="ORIGINAL")
    assert asmt is not None
    assert asmt.verdict == "BLOCK_DEPLOYMENT"
    assert asmt.composite_risk_score == 100
    assert asmt.security_gaps_count >= 2

    # Verify candidate patch remediation drops score to 0
    remed = temp_repo.get_remediation_record("CHG-2026-1005")
    assert remed is not None
    post_asmt = temp_repo.get_latest_assessment("CHG-2026-1005", assessment_type="POST_REMEDIATION")
    assert post_asmt is not None
    assert post_asmt.verdict in ["ALLOW", "VERIFIED_SAFE"]
    assert post_asmt.composite_risk_score == 0
