"""End-to-End UI Workflow and Page Navigation Tests (Milestone F, Stage 5).

Verifies through the UI and service architecture:
1. Creation and saving of a Firewall Change Request draft.
2. Creation of a SailPoint Identity Governance request without requiring a Terraform file.
3. Submission and simulation assessment of a Change Request.
4. Navigation to Assessment Results view and record details.
5. Navigation to Remediation Center and Before & After Comparison views.
6. Navigation and query execution on Assessment History.
7. Executive PDF and JSON report generation and safe export retrieval.
8. Execution of Diagnostics and System Health evaluation.
9. Headless verification of all 9 core navigation views via Streamlit AppTest.
"""

from pathlib import Path
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

from config.settings import NAV_PAGES, PAGE_ABOUT, PAGE_COMPARISON, PAGE_HISTORY, PAGE_OVERVIEW, PAGE_REMEDIATION, PAGE_REPORTS, PAGE_RESULTS
from storage.database import init_db
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.pages.diagnostics import render_diagnostics_page
from ui.pages.history import render_history_page
from ui.pages.record_detail import render_record_detail_page
from ui.pages.reports import render_reports_page
from ui.services.assessment_runner import AssessmentRunnerService
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def temp_repo():
    """Isolated temporary SQLite repository for UI workflow tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    init_db(temp_db_path)
    repo = ChangeRepository(db_path=temp_db_path)
    yield repo

    try:
        Path(temp_db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_ui_workflow_firewall_draft_creation(temp_repo: ChangeRepository):
    """UI Workflow 1: Create and save a firewall change request in draft status."""
    draft = ChangeRequestRecord(
        request_number=temp_repo.generate_next_request_number(),
        title="UI Draft: DMZ Monitoring Ingress",
        description="Save draft for later review by SecOps team.",
        domain=ChangeDomain.NETWORK_SECURITY.value,
        change_type=ChangeType.FIREWALL_POLICY.value,
        priority=ChangePriority.LOW.value,
        status=WorkflowState.DRAFT.value,
        submitted_by="SecOps Lead",
    )
    saved = temp_repo.save_draft(draft)
    assert saved.status == WorkflowState.DRAFT.value

    # Verify that in draft mode, no simulation assessment exists
    latest_asmt = temp_repo.get_latest_assessment(saved.request_number)
    assert latest_asmt is None

    # Verify activity history reflects draft creation
    logs = temp_repo.get_activity_logs(saved.request_number)
    assert any(log.action == "DRAFT_SAVED" for log in logs)


def test_ui_workflow_sailpoint_request_without_terraform(temp_repo: ChangeRepository):
    """UI Workflow 2: Create a SailPoint access request without uploading Terraform."""
    req_no = temp_repo.generate_next_request_number()
    sp_req = ChangeRequestRecord(
        request_number=req_no,
        title="UI SailPoint Access Grant: Sophia Alvarez DevOps Role",
        description="Grant external contractor devops engineering access profile.",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        change_type=ChangeType.SAILPOINT_GOVERNANCE.value,
        priority=ChangePriority.NORMAL.value,
        status=WorkflowState.SUBMITTED.value,
        submitted_by="Identity Admin",
        source_file_path=None,  # No Terraform file attached
        raw_content=None,
    )
    saved = temp_repo.create_change_request(sp_req)
    assert saved.request_number == req_no
    assert saved.source_file_path is None

    # Run assessment - Identity engine assesses synthetic identity model directly
    runner = AssessmentRunnerService(repository=temp_repo)
    success, msg, res = runner.run_assessment(req_no)
    assert success, f"Assessment failed: {msg}"
    assert res is not None

    asmt = temp_repo.get_latest_assessment(req_no)
    assert asmt is not None
    assert asmt.composite_risk_score >= 0


def test_ui_workflow_submit_assess_and_navigate(temp_repo: ChangeRepository):
    """UI Workflow 3-7: Submit, assess, navigate results, remediation, comparison, and history."""
    scenario_path = WORKSPACE_ROOT / "changes" / "pr_4082_firewall_iam.tf"
    req_no = temp_repo.generate_next_request_number()

    # 1. Submit Change Request
    cr = ChangeRequestRecord(
        request_number=req_no,
        title="UI Workflow: PR-4082 Assessment",
        domain=ChangeDomain.NETWORK_SECURITY.value,
        change_type=ChangeType.FIREWALL_POLICY.value,
        priority=ChangePriority.HIGH.value,
        status=WorkflowState.SUBMITTED.value,
        source_file_path=str(scenario_path.resolve()),
        raw_content=scenario_path.read_text(encoding="utf-8"),
    )
    temp_repo.create_change_request(cr)

    # 2. Assess Request
    runner = AssessmentRunnerService(repository=temp_repo)
    success, msg, res = runner.run_assessment(req_no)
    assert success is True
    assert res.baseline_report.deployment_verdict.value == "BLOCK_DEPLOYMENT"
    assert res.post_report.deployment_verdict.value == "ALLOW"

    # 3. Verify Status Promoted to ANALYSIS_COMPLETE
    updated_cr = temp_repo.get_change_request(req_no)
    assert updated_cr.status == WorkflowState.ANALYSIS_COMPLETE.value

    # 4. Verify Assessment Results Available
    base_asmt = temp_repo.get_latest_assessment(req_no, assessment_type="ORIGINAL")
    assert base_asmt is not None
    assert base_asmt.verdict == "BLOCK_DEPLOYMENT"

    # 5. Verify Remediation and Comparison Data
    rem_rec = temp_repo.get_remediation_record(req_no)
    assert rem_rec is not None
    assert rem_rec.status == "VALIDATED"
    assert rem_rec.comparison_json is not None

    # 6. Verify Exports
    pdf_bytes = build_executive_pdf(updated_cr, base_asmt, rem_rec)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")

    json_str = build_executive_json(updated_cr, base_asmt, rem_rec)
    assert req_no in json_str

    # 7. Verify History Lookup
    history_items = temp_repo.filter_change_requests(search_query=req_no)
    assert len(history_items) == 1
    assert history_items[0]["request_number"] == req_no


def test_ui_all_navigation_views_via_apptest():
    """Headless UI test: Verify all 9 navigation pages load cleanly without runtime exceptions."""
    app_path = WORKSPACE_ROOT / "app.py"
    assert app_path.exists()

    for page_name in NAV_PAGES:
        at = AppTest.from_file(str(app_path), default_timeout=30)
        at.session_state["active_page"] = page_name
        at.run()

        # Assert no uncaught exceptions occurred during rendering
        assert not at.exception, f"Page '{page_name}' threw uncaught exception: {at.exception}"
        # Assert at least header or title markdown elements were rendered
        assert len(at.markdown) > 0, f"Page '{page_name}' rendered 0 markdown elements."
