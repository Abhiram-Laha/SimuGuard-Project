"""End-to-End Workflow Tests for Enterprise Firewall & Cloud Changes (Milestone F, Stage 4).

Tests complete 15-step operational lifecycle for:
- changes/pr_4082_firewall_iam.tf
- changes/pr_4083_firewall_iam.tf
- changes/allow_netflix.tf

Verifies draft creation, submission, pre-flight simulation, findings, candidate overlay validation,
before-and-after comparison, PDF/JSON export, historical persistence, and original file immutability.
"""

import hashlib
import json
from pathlib import Path
import tempfile
import pytest

from config.settings import CHANGES_DIR
from storage.database import init_db
from storage.models import (
    AssessmentRecord,
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    RemediationRecord,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService
from ui.services.report_export_service import (
    build_executive_json,
    build_executive_pdf,
    get_safe_export_filename,
)


def _compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file to verify immutability."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def temp_repo(tmp_path: Path) -> ChangeRepository:
    """Isolated temporary SQLite repository for E2E testing."""
    db_file = tmp_path / "test_firewall_e2e.db"
    init_db(db_file)
    return ChangeRepository(db_path=str(db_file))


@pytest.mark.parametrize(
    "scenario_filename,expected_initial_verdict",
    [
        ("pr_4082_firewall_iam.tf", "BLOCK_DEPLOYMENT"),
        ("pr_4083_firewall_iam.tf", "BLOCK_DEPLOYMENT"),
        ("allow_netflix.tf", "WARN_MANUAL_REVIEW"),
    ],
)
def test_firewall_e2e_full_lifecycle(
    temp_repo: ChangeRepository,
    scenario_filename: str,
    expected_initial_verdict: str,
):
    """Execute complete 15-step end-to-end workflow for real scenario file."""
    source_scenario_path = CHANGES_DIR / scenario_filename
    assert source_scenario_path.exists(), f"Scenario file {scenario_filename} must exist"

    # Capture initial SHA-256 hash to assert strict immutability
    initial_hash = _compute_file_hash(source_scenario_path)
    initial_bytes = source_scenario_path.read_bytes()

    req_number = temp_repo.generate_next_request_number()
    raw_tf_content = source_scenario_path.read_text(encoding="utf-8")

    # Step 1: Create Change Request Record
    change_req = ChangeRequestRecord(
        request_number=req_number,
        title=f"E2E Test: {scenario_filename}",
        description=f"Automated evaluation of {scenario_filename} against enterprise Digital Twin.",
        justification="E2E pre-deployment security verification.",
        submitted_by="DevSecOps E2E Pipeline",
        submitter_role="Network Security Operations",
        change_type=ChangeType.FIREWALL_POLICY.value,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=ChangePriority.NORMAL.value,
        status=WorkflowState.DRAFT.value,
        configuration_item="PAN-NGFW-EDGE-01",
        affected_application="Customer Web Portal",
        infrastructure_platform="Palo Alto Networks PAN-OS 11.1",
        scenario_name=scenario_filename,
        source_file_path=str(source_scenario_path.resolve()),
        raw_content=raw_tf_content,
    )

    # Step 2: Save as Draft
    draft_record = temp_repo.save_draft(change_req)
    assert draft_record.status == WorkflowState.DRAFT.value
    # Step 2 Verification: Ensure no assessment was generated in draft state
    assert temp_repo.get_latest_assessment(req_number) is None

    # Step 3: Submit Request
    submitted_record = temp_repo.submit_change_request(draft_record)
    assert submitted_record.status == WorkflowState.SUBMITTED.value

    # Step 4: Run Security Assessment via AssessmentRunnerService
    runner = AssessmentRunnerService(repository=temp_repo)
    success, message, result = runner.run_assessment(req_number, force_reassessment=False)
    assert success, f"Simulation assessment failed: {message}"
    assert result is not None
    assert result.baseline_report is not None

    # Step 5: Verify Persisted Baseline Assessment
    saved_asmt = temp_repo.get_latest_assessment(req_number, assessment_type="ORIGINAL")
    assert saved_asmt is not None
    assert saved_asmt.request_number == req_number
    assert saved_asmt.verdict == expected_initial_verdict
    assert saved_asmt.composite_risk_score > 0
    assert saved_asmt.raw_json is not None

    # Parse raw report
    raw_asmt_data = json.loads(saved_asmt.raw_json)
    assert "identified_security_gaps" in raw_asmt_data
    assert len(raw_asmt_data["identified_security_gaps"]) >= 1

    # Step 6: Inspect Affected Digital Twin Assets
    affected_assets = raw_asmt_data.get("predicted_affected_assets", [])
    if scenario_filename in ["pr_4082_firewall_iam.tf", "pr_4083_firewall_iam.tf"]:
        assert len(affected_assets) >= 1
        assert any("DIRECT" in str(a.get("tier") or a.get("blast_tier")) for a in affected_assets)
    else:
        # allow_netflix uses unmapped security group -> isolated or unmapped impact
        assert saved_asmt.verdict == "WARN_MANUAL_REVIEW"

    # Step 7 & 8: Verify Candidate Remediation Plan & Synthesized Candidate Config
    remediation_record = temp_repo.get_remediation_record(req_number)
    assert remediation_record is not None
    assert remediation_record.synthesized_hcl is not None
    assert len(remediation_record.synthesized_hcl) > 20
    assert remediation_record.plan_json is not None

    plan_json = json.loads(remediation_record.plan_json)
    assert len(plan_json.get("recommendations", [])) >= 1

    # Step 9 & 10: Verify Candidate Overlay & Recalculated Blast Radius
    assert result.overlay_result is not None
    assert result.overlay_result.overlay_applied is True
    assert isinstance(result.overlay_result.removed_relationships, list)
    assert isinstance(result.overlay_result.added_relationships, list)

    # Step 11: Validate Candidate Configuration
    assert result.post_report is not None
    saved_post_asmt = temp_repo.get_latest_assessment(req_number, assessment_type="POST_REMEDIATION")
    assert saved_post_asmt is not None
    assert saved_post_asmt.composite_risk_score <= saved_asmt.composite_risk_score

    # Step 12: Compare Original and Candidate Assessments
    assert result.comparison_report is not None
    assert remediation_record.comparison_json is not None
    comp_json = json.loads(remediation_record.comparison_json)
    assert comp_json["risk_score_delta"] >= 0
    assert comp_json["resolved_count"] >= 1
    assert comp_json["verdict_before"] == expected_initial_verdict

    # Step 13: Export PDF and JSON Reports
    pdf_bytes = build_executive_pdf(
        request_record=submitted_record,
        assessment_record=saved_asmt,
        remediation_record=remediation_record,
    )
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1000

    json_str = build_executive_json(
        request_record=submitted_record,
        assessment_record=saved_asmt,
        remediation_record=remediation_record,
    )
    json_data = json.loads(json_str)
    assert json_data["schema_version"] == "1.0.0"
    assert json_data["change_request"]["request_number"] == req_number
    assert json_data["assessment"]["verdict"] == expected_initial_verdict

    # Step 14: Reopen Request from History & Lookup
    reopened_record = temp_repo.get_change_request(req_number)
    assert reopened_record is not None
    assert reopened_record.request_number == req_number
    assert reopened_record.title == change_req.title

    history_list = temp_repo.filter_change_requests(search_query=req_number)
    assert len(history_list) == 1
    assert history_list[0]["request_number"] == req_number

    # Step 15: Verify Assessment & Report Associated to Correct Request ID
    all_asmts = temp_repo.list_assessments_for_request(req_number)
    assert len(all_asmts) == 2  # ORIGINAL + POST_REMEDIATION
    assert all(a.request_number == req_number for a in all_asmts)

    safe_pdf_name = get_safe_export_filename(req_number, saved_asmt.assessment_id, "pdf")
    assert req_number in safe_pdf_name
    assert saved_asmt.assessment_id in safe_pdf_name

    # FINAL STRICT SAFETY ASSERTION: Verify Original Scenario File Was NEVER Mutated
    final_hash = _compute_file_hash(source_scenario_path)
    final_bytes = source_scenario_path.read_bytes()
    assert initial_hash == final_hash, f"CRITICAL DEFECT: Original file {scenario_filename} was modified!"
    assert initial_bytes == final_bytes, f"CRITICAL DEFECT: Original bytes of {scenario_filename} changed!"
