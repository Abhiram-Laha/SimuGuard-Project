"""Tests for SimuGuard AI Dashboard storage, repository, and UI components (Phase 6 Milestone B)."""

import sqlite3
import pytest
from pathlib import Path

from storage.database import init_db, get_db_connection
from storage.models import (
    ChangeRequestRecord,
    AssessmentRecord,
    RemediationRecord,
    WorkflowState,
    ChangeType,
    ChangePriority,
    ChangeDomain,
    KPISummary,
)
from storage.repository import ChangeRepository
from ui.components.status_badges import (
    render_verdict_badge,
    render_workflow_badge,
    render_priority_badge,
    render_risk_score_badge,
)


@pytest.fixture
def temp_db(tmp_path: Path):
    """Fixture providing a temporary SQLite database path."""
    db_file = tmp_path / "test_simuguard.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def repo(temp_db: Path):
    """Fixture providing a ChangeRepository bound to the temporary database."""
    return ChangeRepository(db_path=str(temp_db))


class TestDatabaseSchema:
    """Verify database schema creation and table constraints."""

    def test_tables_created(self, temp_db: Path):
        conn = get_db_connection(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        conn.close()

        expected = {"change_requests", "assessment_records", "remediation_records", "activity_logs"}
        assert expected.issubset(tables)

    def test_foreign_keys_pragmas_enabled(self, temp_db: Path):
        conn = get_db_connection(temp_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys;")
        fk_status = cursor.fetchone()[0]
        conn.close()
        assert fk_status == 1


class TestChangeRepositoryCRUD:
    """Verify CRUD and sequencing logic in ChangeRepository."""

    def test_generate_next_request_number_empty(self, repo: ChangeRepository):
        req_no = repo.generate_next_request_number()
        assert req_no == "SIM-CHG-000001"

    def test_generate_next_request_number_sequential(self, repo: ChangeRepository):
        req1 = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Firewall rule update",
            submitted_by="Engineer A",
        )
        repo.create_change_request(req1)

        req_no_2 = repo.generate_next_request_number()
        assert req_no_2 == "SIM-CHG-000002"

        req2 = ChangeRequestRecord(
            request_number=req_no_2,
            title="AWS IAM role update",
            submitted_by="Engineer B",
        )
        repo.create_change_request(req2)

        req_no_3 = repo.generate_next_request_number()
        assert req_no_3 == "SIM-CHG-000003"

    def test_create_and_get_change_request(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number="SIM-CHG-000001",
            title="Open Ingress Port 443",
            description="Allow partner ingress for billing API",
            submitted_by="Alice",
            submitter_role="Network Security Operations",
            change_type=ChangeType.FIREWALL_POLICY.value,
            domain=ChangeDomain.NETWORK_SECURITY.value,
            priority=ChangePriority.EXPEDITED.value,
            status=WorkflowState.SUBMITTED.value,
            assigned_engineer="SecOps Operations",
            target_environment="Apex Global Production",
            source_file_path="changes/pr_4081.tf",
            raw_content='resource "panos_security_policy" "rule" {}',
        )
        saved = repo.create_change_request(req)
        assert saved.request_number == "SIM-CHG-000001"

        retrieved = repo.get_change_request("SIM-CHG-000001")
        assert retrieved is not None
        assert retrieved.title == "Open Ingress Port 443"
        assert retrieved.priority == ChangePriority.EXPEDITED.value
        assert retrieved.change_type == ChangeType.FIREWALL_POLICY.value
        assert retrieved.raw_content == 'resource "panos_security_policy" "rule" {}'

        # Verify automatic activity log
        logs = repo.get_activity_logs("SIM-CHG-000001")
        assert len(logs) == 1
        assert logs[0].action == "REQUEST_CREATED"
        assert logs[0].actor == "Alice"

    def test_get_nonexistent_change_request(self, repo: ChangeRepository):
        assert repo.get_change_request("SIM-CHG-999999") is None

    def test_update_change_request_status(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number="SIM-CHG-000001",
            title="Test Request",
            submitted_by="Bob",
        )
        repo.create_change_request(req)

        repo.update_change_request_status("SIM-CHG-000001", WorkflowState.ANALYSIS_COMPLETE.value)
        updated = repo.get_change_request("SIM-CHG-000001")
        assert updated.status == WorkflowState.ANALYSIS_COMPLETE.value

        logs = repo.get_activity_logs("SIM-CHG-000001")
        assert len(logs) == 2
        assert logs[1].action == "STATUS_UPDATED"
        assert WorkflowState.ANALYSIS_COMPLETE.value in logs[1].details

    def test_list_change_requests(self, repo: ChangeRepository):
        assert len(repo.list_change_requests()) == 0

        repo.create_change_request(ChangeRequestRecord(request_number="SIM-CHG-000001", title="Req 1"))
        repo.create_change_request(ChangeRequestRecord(request_number="SIM-CHG-000002", title="Req 2"))

        listed = repo.list_change_requests(limit=10)
        assert len(listed) == 2
        req_numbers = {r.request_number for r in listed}
        assert req_numbers == {"SIM-CHG-000001", "SIM-CHG-000002"}


class TestAssessmentsAndRemediations:
    """Verify assessment and remediation persistence and querying."""

    def test_save_and_retrieve_assessment(self, repo: ChangeRepository):
        repo.create_change_request(
            ChangeRequestRecord(request_number="SIM-CHG-000001", title="Firewall PR")
        )

        assessment = AssessmentRecord(
            assessment_id="asmt-uuid-001",
            request_number="SIM-CHG-000001",
            verdict="BLOCK_DEPLOYMENT",
            composite_risk_score=85.5,
            max_risk_score=90.0,
            security_gaps_count=3,
            critical_count=1,
            high_count=2,
            medium_count=0,
            low_count=0,
            blast_radius_nodes_count=12,
            assessment_type="ORIGINAL",
            raw_json='{"verdict": "BLOCK_DEPLOYMENT"}',
        )
        repo.save_assessment_record(assessment)

        latest = repo.get_latest_assessment("SIM-CHG-000001")
        assert latest is not None
        assert latest.assessment_id == "asmt-uuid-001"
        assert latest.verdict == "BLOCK_DEPLOYMENT"
        assert latest.composite_risk_score == 85.5
        assert latest.security_gaps_count == 3
        assert latest.blast_radius_nodes_count == 12

    def test_assessment_type_filtering(self, repo: ChangeRepository):
        repo.create_change_request(
            ChangeRequestRecord(request_number="SIM-CHG-000001", title="IAM PR")
        )

        orig = AssessmentRecord(
            assessment_id="asmt-001",
            request_number="SIM-CHG-000001",
            timestamp="2026-11-16T01:00:00",
            verdict="BLOCK_DEPLOYMENT",
            composite_risk_score=80.0,
            assessment_type="ORIGINAL",
        )
        post = AssessmentRecord(
            assessment_id="asmt-002",
            request_number="SIM-CHG-000001",
            timestamp="2026-11-16T01:10:00",
            verdict="ALLOW",
            composite_risk_score=15.0,
            assessment_type="POST_REMEDIATION",
        )
        repo.save_assessment_record(orig)
        repo.save_assessment_record(post)

        latest_orig = repo.get_latest_assessment("SIM-CHG-000001", assessment_type="ORIGINAL")
        assert latest_orig.assessment_id == "asmt-001"
        assert latest_orig.verdict == "BLOCK_DEPLOYMENT"

        latest_post = repo.get_latest_assessment("SIM-CHG-000001", assessment_type="POST_REMEDIATION")
        assert latest_post.assessment_id == "asmt-002"
        assert latest_post.verdict == "ALLOW"

    def test_save_and_retrieve_remediation(self, repo: ChangeRepository):
        repo.create_change_request(
            ChangeRequestRecord(request_number="SIM-CHG-000001", title="Firewall PR")
        )
        assessment = AssessmentRecord(
            assessment_id="asmt-001",
            request_number="SIM-CHG-000001",
            verdict="BLOCK_DEPLOYMENT",
            composite_risk_score=90.0,
        )
        repo.save_assessment_record(assessment)

        rem = RemediationRecord(
            remediation_id="rem-001",
            request_number="SIM-CHG-000001",
            assessment_id="asmt-001",
            synthesized_hcl='resource "panos_security_policy" "fixed" {}',
            plan_json='{"status": "GENERATED"}',
            status="VALIDATED",
        )
        repo.save_remediation_record(rem)

        retrieved_rem = repo.get_remediation_record("SIM-CHG-000001")
        assert retrieved_rem is not None
        assert retrieved_rem.remediation_id == "rem-001"
        assert retrieved_rem.status == "VALIDATED"
        assert 'panos_security_policy' in retrieved_rem.synthesized_hcl

    def test_foreign_key_cascade_deletion(self, temp_db: Path, repo: ChangeRepository):
        repo.create_change_request(
            ChangeRequestRecord(request_number="SIM-CHG-000001", title="Cascade Test")
        )
        repo.save_assessment_record(
            AssessmentRecord(
                assessment_id="asmt-cascade",
                request_number="SIM-CHG-000001",
                verdict="ALLOW",
            )
        )
        repo.save_remediation_record(
            RemediationRecord(
                remediation_id="rem-cascade",
                request_number="SIM-CHG-000001",
                assessment_id="asmt-cascade",
            )
        )

        conn = get_db_connection(temp_db)
        conn.execute("DELETE FROM change_requests WHERE request_number = ?", ("SIM-CHG-000001",))
        conn.commit()

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM assessment_records WHERE request_number = 'SIM-CHG-000001'")
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM remediation_records WHERE request_number = 'SIM-CHG-000001'")
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM activity_logs WHERE request_number = 'SIM-CHG-000001'")
        assert cursor.fetchone()[0] == 0
        conn.close()


class TestKPISummaryAndRecentAssessments:
    """Verify aggregated metrics and recent assessment joins."""

    def test_kpi_summary_empty(self, repo: ChangeRepository):
        kpi = repo.get_kpi_summary()
        assert kpi.total_requests == 0
        assert kpi.allowed_count == 0
        assert kpi.warn_count == 0
        assert kpi.blocked_count == 0
        assert kpi.remediated_count == 0
        assert kpi.avg_risk_score == 0.0

    def test_kpi_summary_populated(self, repo: ChangeRepository):
        # Create 3 requests
        repo.create_change_request(ChangeRequestRecord(request_number="SIM-CHG-000001", title="Req 1"))
        repo.create_change_request(ChangeRequestRecord(request_number="SIM-CHG-000002", title="Req 2"))
        repo.create_change_request(ChangeRequestRecord(request_number="SIM-CHG-000003", title="Req 3"))

        # Assessments
        repo.save_assessment_record(
            AssessmentRecord(
                assessment_id="a1",
                request_number="SIM-CHG-000001",
                verdict="BLOCK_DEPLOYMENT",
                composite_risk_score=80.0,
            )
        )
        repo.save_assessment_record(
            AssessmentRecord(
                assessment_id="a2",
                request_number="SIM-CHG-000002",
                verdict="WARN_MANUAL_REVIEW",
                composite_risk_score=40.0,
            )
        )
        repo.save_assessment_record(
            AssessmentRecord(
                assessment_id="a3",
                request_number="SIM-CHG-000003",
                verdict="ALLOW",
                composite_risk_score=0.0,
            )
        )

        # Remediation on Req 1
        repo.save_remediation_record(
            RemediationRecord(
                remediation_id="r1",
                request_number="SIM-CHG-000001",
                assessment_id="a1",
                status="VALIDATED",
            )
        )

        kpi = repo.get_kpi_summary()
        assert kpi.total_requests == 3
        assert kpi.blocked_count == 1
        assert kpi.warn_count == 1
        assert kpi.allowed_count == 1
        assert kpi.remediated_count == 1
        assert kpi.avg_risk_score == round((80.0 + 40.0 + 0.0) / 3, 1)

    def test_recent_assessments_empty(self, repo: ChangeRepository):
        recent = repo.get_recent_assessments()
        assert recent == []

    def test_recent_assessments_joined(self, repo: ChangeRepository):
        repo.create_change_request(
            ChangeRequestRecord(
                request_number="SIM-CHG-000001",
                title="Firewall egress update",
                priority=ChangePriority.EMERGENCY.value,
            )
        )
        repo.save_assessment_record(
            AssessmentRecord(
                assessment_id="asmt-join-1",
                request_number="SIM-CHG-000001",
                verdict="BLOCK_DEPLOYMENT",
                composite_risk_score=92.0,
                security_gaps_count=4,
                blast_radius_nodes_count=8,
            )
        )

        recent = repo.get_recent_assessments(limit=5)
        assert len(recent) == 1
        item = recent[0]
        assert item["request_number"] == "SIM-CHG-000001"
        assert item["title"] == "Firewall egress update"
        assert item["priority"] == "EMERGENCY"
        assert item["verdict"] == "BLOCK_DEPLOYMENT"
        assert item["composite_risk_score"] == 92.0
        assert item["security_gaps_count"] == 4
        assert item["blast_radius_nodes_count"] == 8


class TestStatusBadges:
    """Verify HTML rendering of badges and pills."""

    def test_render_verdict_badge(self):
        allow_badge = render_verdict_badge("ALLOW")
        assert "sg-badge-allow" in allow_badge
        assert "ALLOW" in allow_badge

        warn_badge = render_verdict_badge("WARN_MANUAL_REVIEW")
        assert "sg-badge-warn" in warn_badge
        assert "WARN_MANUAL_REVIEW" in warn_badge

        block_badge = render_verdict_badge("BLOCK_DEPLOYMENT")
        assert "sg-badge-block" in block_badge
        assert "BLOCK_DEPLOYMENT" in block_badge

        pending_badge = render_verdict_badge(None)
        assert "sg-badge-neutral" in pending_badge
        assert "PENDING" in pending_badge

    def test_render_workflow_badge(self):
        approved = render_workflow_badge("APPROVED")
        assert "sg-badge-allow" in approved

        analyzing = render_workflow_badge("ANALYZING")
        assert "sg-badge-purple" in analyzing

        rejected = render_workflow_badge("REJECTED")
        assert "sg-badge-block" in rejected

        submitted = render_workflow_badge("SUBMITTED")
        assert "sg-badge-neutral" in submitted

    def test_render_priority_badge(self):
        emerg = render_priority_badge("EMERGENCY")
        assert "sg-prio-emergency" in emerg

        expedited = render_priority_badge("EXPEDITED")
        assert "sg-prio-expedited" in expedited

        normal = render_priority_badge("NORMAL")
        assert "sg-prio-normal" in normal

    def test_render_risk_score_badge(self):
        high = render_risk_score_badge(85.0)
        assert "sg-badge-block" in high
        assert "85.0 / 100" in high

        medium = render_risk_score_badge(45.0)
        assert "sg-badge-warn" in medium
        assert "45.0 / 100" in medium

        low = render_risk_score_badge(10.0)
        assert "sg-badge-allow" in low
        assert "10.0 / 100" in low
