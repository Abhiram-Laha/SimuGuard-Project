"""Comprehensive integration tests for Phase 6 Milestone D:
Security Analysis, Remediation, and Validation Engine UI Integration.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from config.settings import CHANGES_DIR
from simuguard.models.enums import DeploymentVerdict, Severity
from storage.database import get_db_connection, init_db
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from ui.services.assessment_runner import AssessmentRunnerService


@pytest.fixture
def temp_db(tmp_path: Path):
    """Fixture providing an isolated temporary database path."""
    db_file = tmp_path / "test_simuguard_milestone_d.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def repo(temp_db: Path):
    """Fixture providing a ChangeRepository bound to the test database."""
    return ChangeRepository(db_path=str(temp_db))


@pytest.fixture
def runner(repo: ChangeRepository):
    """Fixture providing an AssessmentRunnerService."""
    return AssessmentRunnerService(repository=repo)


# =============================================================================
# 1. FIREWALL ASSESSMENT EXECUTION & PERSISTENCE
# =============================================================================
class TestFirewallAssessmentExecution:
    """Verifies end-to-end execution of Phase 4 and Phase 5 engines on Firewall PRs."""

    def test_pr_4083_firewall_assessment_execution(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        assert scenario_path.exists()

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="PR-4083 Palo Alto NGFW Ingress",
            description="Testing PR 4083 execution in dashboard engine.",
            justification="Mandatory test justification.",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            change_type=ChangeType.FIREWALL_POLICY.value,
            priority=ChangePriority.HIGH.value,
            status=WorkflowState.SUBMITTED.value,
            source_file_path=str(scenario_path),
            scenario_name="pr_4083_firewall_iam.tf",
        )
        repo.submit_change_request(req)

        # Execute assessment
        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is True, f"Failed with message: {msg}"
        assert res is not None
        assert res.baseline_report is not None

        # Verify gate verdict is BLOCK_DEPLOYMENT due to App-ID bypass, disabled profiles, and S3FullAccess
        assert res.baseline_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert res.baseline_report.overall_risk_score >= 80

        # Verify finding serialization in SQLite
        latest_asmt = repo.get_latest_assessment(req.request_number, assessment_type="ORIGINAL")
        assert latest_asmt is not None
        assert latest_asmt.verdict == "BLOCK_DEPLOYMENT"
        assert latest_asmt.critical_count >= 1
        assert latest_asmt.blast_radius_nodes_count > 0

        # Verify raw JSON contains full report
        report_data = json.loads(latest_asmt.raw_json)
        assert len(report_data["identified_security_gaps"]) >= 2
        rule_ids = {g["rule_id"] for g in report_data["identified_security_gaps"]}
        assert "FW-01" in rule_ids or "FW-02" in rule_ids or "IAM-01" in rule_ids

    def test_allow_netflix_simulation(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "allow_netflix.tf"
        assert scenario_path.exists()

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Allow Netflix Stream PR-4101",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            change_type=ChangeType.FIREWALL_POLICY.value,
            priority=ChangePriority.LOW.value,
            status=WorkflowState.SUBMITTED.value,
            source_file_path=str(scenario_path),
            scenario_name="allow_netflix.tf",
        )
        repo.submit_change_request(req)

        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is True, f"Failed with message: {msg}"
        assert res is not None
        # Schema error on destination=["netflix.com"] results in WARN or BLOCK, never ALLOW
        assert res.baseline_report.deployment_verdict in [
            DeploymentVerdict.WARN_MANUAL_REVIEW,
            DeploymentVerdict.BLOCK_DEPLOYMENT,
        ]


# =============================================================================
# 2. SAILPOINT IDENTITY GOVERNANCE ASSESSMENT
# =============================================================================
class TestSailPointAssessmentExecution:
    """Verifies SailPoint governance evaluation: SoD, in-flight access, and unmapped entities."""

    def test_sailpoint_in_flight_and_unprovisioned_violation(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        # Target identity with PENDING approval and UNPROVISIONED status
        sp_details = SailPointChangeDetails(
            identity_id="sp-ident-sarah-chen",
            identity_name="Sarah Chen",
            requested_role="Finance & Treasury Analyst",
            request_status="PENDING_APPROVAL",
            approval_status="PENDING",
            provisioning_status="UNPROVISIONED",
        )

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Request Finance Role for CISO",
            domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
            change_type=ChangeType.SAILPOINT_GOVERNANCE.value,
            priority=ChangePriority.NORMAL.value,
            status=WorkflowState.SUBMITTED.value,
            sailpoint_details_json=sp_details.model_dump_json(),
        )
        repo.submit_change_request(req)

        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is True, f"Failed with message: {msg}"
        assert res is not None

        # Verify SP-01 (PENDING_IS_NOT_ACCESS) and SP-02 (UNPROVISIONED) were identified
        rule_ids = {g.rule_id for g in res.baseline_report.identified_security_gaps}
        assert "SP-01" in rule_ids
        assert "SP-02" in rule_ids
        # In-flight access assumption is CRITICAL severity, resulting in BLOCK_DEPLOYMENT
        assert res.baseline_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT

    def test_sailpoint_unmapped_identity_is_unknown_not_safe(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        sp_details = SailPointChangeDetails(
            identity_id="sp-ident-unknown-ghost-999",
            identity_name="Ghost User",
            requested_role="Some Role",
            request_status="APPROVED",
            approval_status="APPROVED",
            provisioning_status="PROVISIONED",
        )

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Unmapped User Grant",
            domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
            sailpoint_details_json=sp_details.model_dump_json(),
        )
        repo.submit_change_request(req)

        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is True, f"Failed with message: {msg}"
        # Unmapped entity must generate UNKNOWN finding with HIGH severity, never ALLOW
        assert any(
            "Unmapped" in g.gap_title or g.rule_id == "SP-CORR-01"
            for g in res.baseline_report.identified_security_gaps
        )
        assert res.baseline_report.deployment_verdict != DeploymentVerdict.ALLOW


# =============================================================================
# 3. DUPLICATE EXECUTION & RE-ASSESSMENT PRESERVATION
# =============================================================================
class TestExecutionLifecycleAndReassessment:
    """Verifies duplicate execution prevention and re-assessment history preservation."""

    def test_duplicate_execution_prevented_without_force(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="PR 4082 Test",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            source_file_path=str(scenario_path),
        )
        repo.submit_change_request(req)

        # First run succeeds
        ok1, _, _ = runner.run_assessment(req.request_number)
        assert ok1 is True

        # Second run without force is rejected
        ok2, msg2, _ = runner.run_assessment(req.request_number, force_reassessment=False)
        assert ok2 is False
        assert "already been assessed" in msg2

        # Third run with force_reassessment succeeds
        ok3, _, _ = runner.run_assessment(req.request_number, force_reassessment=True)
        assert ok3 is True

        # Verify assessment history preserved (multiple assessment records linked)
        all_asmts = repo.list_assessments_for_request(req.request_number)
        assert len(all_asmts) >= 2


# =============================================================================
# 4. REMEDIATION GENERATION & CANDIDATE OVERLAY ISOLATION
# =============================================================================
class TestRemediationAndCandidateOverlay:
    """Verifies candidate HCL generation, candidate overlay evaluation, and zero file mutation."""

    def test_remediation_pipeline_preserves_original_file(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        original_bytes_before = scenario_path.read_bytes()

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Remediation Test PR-4083",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            source_file_path=str(scenario_path),
        )
        repo.submit_change_request(req)

        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is True, f"Failed with message: {msg}"
        assert res.remediation_plan is not None
        assert res.post_report is not None
        assert res.comparison_report is not None

        # Verify candidate HCL was synthesized and removed broad access
        cand_hcl = res.remediation_plan.synthesized_candidate_hcl
        assert "panos_security_policy" in cand_hcl
        assert "AmazonS3FullAccess" not in cand_hcl
        assert "scoped" in cand_hcl.lower() or "52.84.120.0" in cand_hcl

        # Critical: Verify original scenario file was NOT modified
        original_bytes_after = scenario_path.read_bytes()
        assert original_bytes_before == original_bytes_after

        # Verify post-remediation achieved risk reduction
        assert res.comparison_report.risk_score_delta > 0
        assert res.comparison_report.resolved_count >= 1

    def test_candidate_overlay_validation_severed_relationships(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Overlay Relationship Test",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            source_file_path=str(scenario_path),
        )
        repo.submit_change_request(req)

        ok, _, res = runner.run_assessment(req.request_number)
        assert ok is True
        assert res.overlay_result is not None
        assert res.overlay_result.overlay_applied is True


# =============================================================================
# 5. FAILURE HANDLING & AUDIT LOGS
# =============================================================================
class TestFailureHandlingAndAuditLogs:
    """Verifies failure handling without crashing and activity log tracking."""

    def test_missing_file_fails_safely_as_block(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Nonexistent File CR",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            source_file_path="nonexistent_path_to_tf_file.tf",
            raw_content=None,
        )
        repo.submit_change_request(req)

        ok, msg, res = runner.run_assessment(req.request_number)
        assert ok is False
        assert "not found" in msg.lower()
        # Verify failure event was logged
        logs = repo.get_activity_logs(req.request_number)
        assert any(l.action == "ASSESSMENT_FAILED" for l in logs)

    def test_activity_timeline_audit_events_created(
        self, repo: ChangeRepository, runner: AssessmentRunnerService
    ):
        scenario_path = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Audit Test CR",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            source_file_path=str(scenario_path),
        )
        repo.submit_change_request(req)
        runner.run_assessment(req.request_number)

        logs = repo.get_activity_logs(req.request_number)
        actions = [l.action for l in logs]
        assert "REQUEST_CREATED" in actions or "REQUEST_SUBMITTED" in actions
        assert "ASSESSMENT_STARTED" in actions
        assert "ASSESSMENT_COMPLETED" in actions
        assert "VALIDATION_COMPLETED" in actions
