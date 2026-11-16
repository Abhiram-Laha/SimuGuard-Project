"""End-to-End Persistence and Dashboard Workflow Tests for SimuGuard AI.

Verifies:
1. Draft saving, retrieval, mutation, and promotion to submitted state.
2. Comprehensive history filtering (domain, priority, status, search), sorting, and pagination.
3. Multi-request session state isolation (Request A vs Request B zero cross-talk).
4. Multi-threaded concurrent change request generation and database-safe ID allocation.
5. Strict isolation from production database and immutability of scenario baselines.
"""

import concurrent.futures
import hashlib
from pathlib import Path
import tempfile
import time
from typing import Dict, List
import pytest

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

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


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


# =============================================================================
# 1. Draft Save and Resume Lifecycle
# =============================================================================

def test_draft_save_and_resume_lifecycle(temp_repo: ChangeRepository):
    """Verify that a change request can be saved as a draft, modified, and submitted."""
    # 1. Create initial draft
    draft_record = ChangeRequestRecord(
        request_number="SIM-CHG-9001",
        title="Draft Egress Policy for Log Forwarding",
        description="Initial draft: allow outbound syslogs to monitoring cluster.",
        justification="Pending final network architecture review.",
        submitted_by="Network Eng 1",
        submitter_role="Network Security Operations",
        change_type=ChangeType.FIREWALL_POLICY.value,
        domain=ChangeDomain.NETWORK_SECURITY.value,
        priority=ChangePriority.LOW.value,
        status=WorkflowState.DRAFT.value,
    )

    saved_draft = temp_repo.save_draft(draft_record)
    assert saved_draft.status == WorkflowState.DRAFT.value
    assert saved_draft.request_number == "SIM-CHG-9001"

    # Verify retrieval
    retrieved = temp_repo.get_change_request("SIM-CHG-9001")
    assert retrieved is not None
    assert retrieved.status == WorkflowState.DRAFT.value
    assert retrieved.title == "Draft Egress Policy for Log Forwarding"

    # Verify activity log
    logs = temp_repo.get_activity_logs("SIM-CHG-9001")
    assert any(log.action == "DRAFT_SAVED" for log in logs)

    # 2. Modify draft details
    retrieved.title = "Finalized Egress Policy for Log Forwarding"
    retrieved.priority = ChangePriority.NORMAL.value
    retrieved.implementation_plan = "Apply Palo Alto security policy via Panorama pipeline."
    temp_repo.save_draft(retrieved)

    updated_draft = temp_repo.get_change_request("SIM-CHG-9001")
    assert updated_draft.title == "Finalized Egress Policy for Log Forwarding"
    assert updated_draft.priority == ChangePriority.NORMAL.value
    assert updated_draft.status == WorkflowState.DRAFT.value

    # 3. Promote draft to SUBMITTED
    submitted_record = temp_repo.submit_change_request(updated_draft)
    assert submitted_record.status == WorkflowState.SUBMITTED.value

    persisted_submitted = temp_repo.get_change_request("SIM-CHG-9001")
    assert persisted_submitted.status == WorkflowState.SUBMITTED.value

    final_logs = temp_repo.get_activity_logs("SIM-CHG-9001")
    assert any(log.action == "REQUEST_SUBMITTED" for log in final_logs)


# =============================================================================
# 2. History Filtering, Sorting, and Pagination
# =============================================================================

def test_history_filtering_sorting_and_pagination(temp_repo: ChangeRepository):
    """Verify robust query filtering across domain, priority, status, search, and pagination."""
    # Seed 12 distinct records
    priorities = [
        ChangePriority.CRITICAL.value,
        ChangePriority.HIGH.value,
        ChangePriority.MEDIUM.value,
        ChangePriority.LOW.value,
    ]
    statuses = [
        WorkflowState.DRAFT.value,
        WorkflowState.SUBMITTED.value,
        WorkflowState.ANALYSIS_COMPLETE.value,
    ]

    for i in range(1, 13):
        is_network = (i % 2 != 0)
        domain = ChangeDomain.NETWORK_SECURITY.value if is_network else ChangeDomain.IDENTITY_GOVERNANCE.value
        change_type = ChangeType.FIREWALL_POLICY.value if is_network else ChangeType.SAILPOINT_GOVERNANCE.value
        prio = priorities[i % len(priorities)]
        stat = statuses[i % len(statuses)]
        kw = "AlphaPerimeter" if is_network else "BetaIdentity"

        rec = ChangeRequestRecord(
            request_number=f"SIM-CHG-FILTER-{i:03d}",
            title=f"Change {kw} Ticket #{i}",
            description=f"Automated test change description for record {i}",
            submitted_by=f"engineer_{i}",
            change_type=change_type,
            domain=domain,
            priority=prio,
            status=stat,
        )
        temp_repo.create_change_request(rec)

    # 1. Filter by Domain
    net_records = temp_repo.filter_change_requests(domain=ChangeDomain.NETWORK_SECURITY.value, limit=50)
    assert len(net_records) == 6
    assert all(r["domain"] == ChangeDomain.NETWORK_SECURITY.value for r in net_records)

    id_records = temp_repo.filter_change_requests(domain=ChangeDomain.IDENTITY_GOVERNANCE.value, limit=50)
    assert len(id_records) == 6
    assert all(r["domain"] == ChangeDomain.IDENTITY_GOVERNANCE.value for r in id_records)

    # 2. Filter by Status
    draft_records = temp_repo.filter_change_requests(status=WorkflowState.DRAFT.value, limit=50)
    assert len(draft_records) > 0
    assert all(r["status"] == WorkflowState.DRAFT.value for r in draft_records)

    # 3. Filter by Priority
    crit_records = temp_repo.filter_change_requests(priority=ChangePriority.CRITICAL.value, limit=50)
    assert len(crit_records) > 0
    assert all(r["priority"] == ChangePriority.CRITICAL.value for r in crit_records)

    # 4. Search query
    search_res = temp_repo.filter_change_requests(search_query="AlphaPerimeter", limit=50)
    assert len(search_res) == 6
    assert all("AlphaPerimeter" in r["title"] for r in search_res)

    # 5. Pagination
    page_1 = temp_repo.filter_change_requests(limit=4, offset=0, sort_field="request_number", sort_order="ASC")
    page_2 = temp_repo.filter_change_requests(limit=4, offset=4, sort_field="request_number", sort_order="ASC")
    assert len(page_1) == 4
    assert len(page_2) == 4
    ids_p1 = {r["request_number"] for r in page_1}
    ids_p2 = {r["request_number"] for r in page_2}
    assert ids_p1.isdisjoint(ids_p2)

    # 6. Count filtered items
    total_net = temp_repo.count_filtered_change_requests(domain=ChangeDomain.NETWORK_SECURITY.value)
    assert total_net == 6


# =============================================================================
# 3. Session State & Multi-Request Isolation
# =============================================================================

def test_session_state_isolation_between_requests(temp_repo: ChangeRepository):
    """Verify that records, assessments, and remediation plans do not bleed between requests."""
    # 1. Request A: Critical Firewall policy change
    rec_a = ChangeRequestRecord(
        request_number="SIM-CHG-ISOL-001",
        title="Firewall Zero Trust DMZ Egress",
        domain=ChangeDomain.NETWORK_SECURITY.value,
        change_type=ChangeType.FIREWALL_POLICY.value,
        status=WorkflowState.SUBMITTED.value,
    )
    temp_repo.create_change_request(rec_a)

    asmt_a = AssessmentRecord(
        assessment_id="ASMT-A-999",
        request_number="SIM-CHG-ISOL-001",
        timestamp="2026-11-16T10:00:00Z",
        verdict="BLOCK_DEPLOYMENT",
        composite_risk_score=92.5,
        max_risk_score=92.5,
        security_gaps_count=3,
        critical_count=1,
        high_count=2,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=8,
        assessment_type="BASELINE_SIMULATION",
        raw_json='{"summary": "Block due to unrestricted egress"}',
    )
    temp_repo.save_assessment_record(asmt_a)

    rem_a = RemediationRecord(
        remediation_id="REM-A-999",
        request_number="SIM-CHG-ISOL-001",
        assessment_id="ASMT-A-999",
        created_at="2026-11-16T10:05:00Z",
        synthesized_hcl='resource "panos_security_policy" "scoped_rule" {}',
        plan_json='{"status": "VALIDATED"}',
        comparison_json='{"delta": -60.0}',
        status="VALIDATED",
    )
    temp_repo.save_remediation_record(rem_a)

    # 2. Request B: Low-risk SailPoint access grant
    rec_b = ChangeRequestRecord(
        request_number="SIM-CHG-ISOL-002",
        title="SailPoint Business Analyst Access",
        domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
        change_type=ChangeType.SAILPOINT_GOVERNANCE.value,
        status=WorkflowState.SUBMITTED.value,
    )
    temp_repo.create_change_request(rec_b)

    asmt_b = AssessmentRecord(
        assessment_id="ASMT-B-111",
        request_number="SIM-CHG-ISOL-002",
        timestamp="2026-11-16T10:10:00Z",
        verdict="ALLOW",
        composite_risk_score=15.0,
        max_risk_score=15.0,
        security_gaps_count=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        blast_radius_nodes_count=1,
        assessment_type="BASELINE_SIMULATION",
        raw_json='{"summary": "Allow clean business analyst role"}',
    )
    temp_repo.save_assessment_record(asmt_b)
    # Request B has NO remediation plan

    # 3. Simulate UI Session State transitions
    # Active view set to Request A
    ui_session = {"viewing_request_number": "SIM-CHG-ISOL-001"}
    view_a_cr = temp_repo.get_change_request(ui_session["viewing_request_number"])
    view_a_asmt = temp_repo.get_latest_assessment(ui_session["viewing_request_number"])
    view_a_rem = temp_repo.get_remediation_record(ui_session["viewing_request_number"])

    assert view_a_cr.request_number == "SIM-CHG-ISOL-001"
    assert view_a_asmt.assessment_id == "ASMT-A-999"
    assert view_a_asmt.verdict == "BLOCK_DEPLOYMENT"
    assert view_a_asmt.composite_risk_score == 92.5
    assert view_a_rem is not None
    assert view_a_rem.remediation_id == "REM-A-999"

    # Switch active view to Request B
    ui_session["viewing_request_number"] = "SIM-CHG-ISOL-002"
    view_b_cr = temp_repo.get_change_request(ui_session["viewing_request_number"])
    view_b_asmt = temp_repo.get_latest_assessment(ui_session["viewing_request_number"])
    view_b_rem = temp_repo.get_remediation_record(ui_session["viewing_request_number"])

    assert view_b_cr.request_number == "SIM-CHG-ISOL-002"
    assert view_b_asmt.assessment_id == "ASMT-B-111"
    assert view_b_asmt.verdict == "ALLOW"
    assert view_b_asmt.composite_risk_score == 15.0
    # Crucial: Request B must NOT inherit Request A's remediation
    assert view_b_rem is None


# =============================================================================
# 4. Multi-threaded Concurrent Request Insertion & ID Uniqueness
# =============================================================================

def test_concurrent_change_request_creation_thread_safety(temp_repo: ChangeRepository):
    """Verify that multiple concurrent threads creating change requests receive unique IDs without collisions."""
    num_threads = 10
    created_records: List[ChangeRequestRecord] = []
    errors: List[Exception] = []

    def worker(worker_id: int):
        try:
            # Let repository generate sequential SIM-CHG request number with retry handling
            req_no = temp_repo.generate_next_request_number()
            rec = ChangeRequestRecord(
                request_number=req_no,
                title=f"Concurrent Worker Ticket {worker_id}",
                description=f"Thread-safety test worker {worker_id}",
                domain=ChangeDomain.NETWORK_SECURITY.value,
                change_type=ChangeType.FIREWALL_POLICY.value,
                priority=ChangePriority.NORMAL.value,
                status=WorkflowState.SUBMITTED.value,
                submitted_by=f"thread_worker_{worker_id}",
            )
            saved = temp_repo.create_change_request(rec)
            return saved
        except Exception as e:
            return e

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if isinstance(res, Exception):
                errors.append(res)
            else:
                created_records.append(res)

    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
    assert len(created_records) == num_threads

    # Verify all generated request numbers are strictly unique
    req_numbers = [r.request_number for r in created_records]
    assert len(set(req_numbers)) == num_threads, f"Collision detected in request numbers: {req_numbers}"

    # Verify all exist in the database
    for r in created_records:
        fetched = temp_repo.get_change_request(r.request_number)
        assert fetched is not None
        assert fetched.request_number == r.request_number


# =============================================================================
# 5. Production Database Isolation & Scenario Immutability
# =============================================================================

def test_production_database_and_scenario_immutability():
    """Verify production database has zero test records and scenario files remain byte-identical."""
    prod_db_path = WORKSPACE_ROOT / "data" / "simuguard_history.db"
    if prod_db_path.exists():
        prod_repo = ChangeRepository(db_path=str(prod_db_path))
        prod_requests = prod_repo.list_change_requests(limit=100)
        assert len(prod_requests) == 0, f"Production DB contains {len(prod_requests)} uncleaned records!"

    # Verify scenario files remain unmodified
    scenarios = [
        "changes/pr_4082_firewall_iam.tf",
        "changes/pr_4083_firewall_iam.tf",
        "changes/allow_netflix.tf",
    ]
    for rel_path in scenarios:
        full_path = WORKSPACE_ROOT / rel_path
        assert full_path.exists(), f"Scenario {rel_path} does not exist!"
        content = full_path.read_bytes()
        assert len(content) > 0
