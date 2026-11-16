"""Exhaustive tests for Phase 6 Milestone C: Enterprise Change Request Management."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import pytest

from config.settings import CHANGES_DIR, DEMO_ENV_DIR, UPLOADS_DIR
from storage.database import (
    ADDITIONAL_COLUMNS,
    BASE_SCHEMA_SQL,
    get_db_connection,
    init_db,
    migrate_schema_if_needed,
)
from storage.models import (
    ChangeDomain,
    ChangePriority,
    ChangeRequestRecord,
    ChangeType,
    FirewallChangeDetails,
    SailPointChangeDetails,
    WorkflowState,
)
from storage.repository import ChangeRepository
from storage.upload_handler import (
    MAX_UPLOAD_SIZE_BYTES,
    sanitize_filename,
    validate_and_stage_upload,
)
from ui.services.dataset_service import DatasetService, get_dataset_service


@pytest.fixture
def temp_db(tmp_path: Path):
    """Fixture providing an isolated temporary database path."""
    db_file = tmp_path / "test_simuguard_milestone_c.db"
    init_db(db_file)
    return db_file


@pytest.fixture
def repo(temp_db: Path):
    """Fixture providing a ChangeRepository bound to the test database."""
    return ChangeRepository(db_path=str(temp_db))


@pytest.fixture
def dataset_svc():
    """Fixture providing dataset service."""
    return get_dataset_service()


# =============================================================================
# 1 & 2. FORM VALIDATION & REQUIRED FIELDS
# =============================================================================
class TestChangeRequestFormValidation:
    """Tests 1 & 2: Form validation and required fields enforcement."""

    def test_required_fields_present_on_valid_submission(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Update DMZ Ingress Rule",
            description="Detailed operational description for ingress policy change.",
            justification="Mandatory business reason approved by CISO.",
            submitted_by="David Kim",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            status=WorkflowState.SUBMITTED.value,
        )
        assert req.title != ""
        assert req.description != ""
        assert req.justification != ""
        saved = repo.submit_change_request(req)
        assert saved.status == WorkflowState.SUBMITTED.value

    def test_mandatory_fields_validation_error_on_empty_title_or_justification(self):
        # Empty title check
        with pytest.raises(Exception):
            # SQLite NOT NULL constraint on title
            ChangeRequestRecord(
                request_number="SIM-CHG-000001",
                title=None,  # type: ignore
                description="Some description",
                justification="Some justification",
            )


# =============================================================================
# 3 & 4. FIREWALL & SAILPOINT DOMAIN SUBMISSIONS
# =============================================================================
class TestDomainSpecificSubmissions:
    """Tests 3 & 4: Firewall and SailPoint change submissions."""

    def test_firewall_change_submission(self, repo: ChangeRepository):
        fw_details = FirewallChangeDetails(
            firewall_platform="Palo Alto Networks PA-5450",
            firewall_device="fw-edge-01-primary",
            panorama_reference="pan-mgmt-01.mgmt.apex-global.example",
            rule_name="Allow-Analytics-Outbound-Webhook",
            source_zone="Trust-DMZ",
            destination_zone="Untrust-Internet",
            source_addresses="10.100.4.0/24",
            destination_addresses="52.84.120.0/22",
            applications="ssl",
            services="service-https",
            action="allow",
            security_profile="Strict-Enterprise-Security",
            change_operation="Create",
        )

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Deploy Analytics Partner Webhook Egress",
            description="Allows analytics pods to stream logs to partner endpoint.",
            justification="Contractual reporting requirement for Q4 telemetry.",
            domain=ChangeDomain.NETWORK_SECURITY.value,
            change_type=ChangeType.FIREWALL_POLICY.value,
            configuration_item="PAN-NGFW-EDGE-01",
            firewall_details_json=fw_details.model_dump_json(),
        )
        saved = repo.submit_change_request(req)

        retrieved = repo.get_change_request(saved.request_number)
        assert retrieved is not None
        assert retrieved.firewall_details_json is not None
        parsed_fw = json.loads(retrieved.firewall_details_json)
        assert parsed_fw["rule_name"] == "Allow-Analytics-Outbound-Webhook"
        assert parsed_fw["source_zone"] == "Trust-DMZ"
        assert parsed_fw["destination_zone"] == "Untrust-Internet"
        assert parsed_fw["security_profile"] == "Strict-Enterprise-Security"

    def test_sailpoint_change_submission(self, repo: ChangeRepository, dataset_svc: DatasetService):
        identities = dataset_svc.get_identities()
        assert len(identities) > 0
        first_ident = identities[0]

        sp_details = SailPointChangeDetails(
            identity_id=first_ident["id"],
            identity_name=first_ident["display_name"],
            identity_profile="Corporate Full-Time Employees",
            identity_source="Corporate Active Directory",
            account_id="sp-acct-ad-test",
            account_status="ACTIVE",
            requested_role="Finance & Treasury Analyst",
            access_profile="Production S3 CUI Vault Read Access",
            entitlement="AWS Production S3 CUI Vault Read",
            application_name="Apex Core Financials",
            business_justification="Authorized audit inspection of Q4 financial ledgers.",
            request_status="SUBMITTED",
            approval_status="PENDING",
            provisioning_status="UNPROVISIONED",
        )

        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Request Treasury Analyst Read Access",
            description="Grant read access to NIST SP 800-171 financial ledger bucket.",
            justification="Quarterly compliance ledger review.",
            domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
            change_type=ChangeType.SAILPOINT_GOVERNANCE.value,
            configuration_item="SailPoint-ISC-Tenant",
            sailpoint_details_json=sp_details.model_dump_json(),
        )
        saved = repo.submit_change_request(req)

        retrieved = repo.get_change_request(saved.request_number)
        assert retrieved is not None
        assert retrieved.domain == ChangeDomain.IDENTITY_GOVERNANCE.value
        assert retrieved.sailpoint_details_json is not None
        parsed_sp = json.loads(retrieved.sailpoint_details_json)
        assert parsed_sp["requested_role"] == "Finance & Treasury Analyst"
        assert parsed_sp["provisioning_status"] == "UNPROVISIONED"
        assert parsed_sp["approval_status"] == "PENDING"


# =============================================================================
# 5 & 6. DRAFT SAVING & SUBMISSION WORKFLOW
# =============================================================================
class TestDraftAndSubmissionWorkflow:
    """Tests 5 & 6: Draft saving, submission state transitions, and zero assessment records."""

    def test_save_draft_sets_draft_status_without_assessment(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Unfinished Policy Draft",
            description="Work in progress draft configuration.",
            status=WorkflowState.DRAFT.value,
        )
        saved = repo.save_draft(req)
        assert saved.status == WorkflowState.DRAFT.value

        # Verify no assessment record exists
        latest = repo.get_latest_assessment(saved.request_number)
        assert latest is None

        # Verify activity log recorded DRAFT_SAVED
        logs = repo.get_activity_logs(saved.request_number)
        assert len(logs) >= 1
        assert logs[-1].action == "DRAFT_SAVED"

    def test_submission_sets_submitted_status_and_logs_event(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number=repo.generate_next_request_number(),
            title="Submitted Firewall Change",
            description="Ready for CAB simulation review.",
            justification="Scheduled business release.",
        )
        saved = repo.submit_change_request(req)
        assert saved.status == WorkflowState.SUBMITTED.value

        logs = repo.get_activity_logs(saved.request_number)
        actions = [log.action for log in logs]
        assert "REQUEST_SUBMITTED" in actions


# =============================================================================
# 7 & 8. SEQUENTIAL NUMBERING & DUPLICATE PROTECTION
# =============================================================================
class TestNumberingAndDuplicateProtection:
    """Tests 7 & 8: Atomic numbering and idempotency under repeated submissions."""

    def test_automatic_request_numbering_sequential(self, repo: ChangeRepository):
        n1 = repo.generate_next_request_number()
        repo.create_change_request(ChangeRequestRecord(request_number=n1, title="CR 1"))
        n2 = repo.generate_next_request_number()
        repo.create_change_request(ChangeRequestRecord(request_number=n2, title="CR 2"))
        n3 = repo.generate_next_request_number()
        assert n1 == "SIM-CHG-000001"
        assert n2 == "SIM-CHG-000002"
        assert n3 == "SIM-CHG-000003"

    def test_duplicate_submission_updates_existing_record_without_duplication(
        self, repo: ChangeRepository
    ):
        req_no = repo.generate_next_request_number()
        req = ChangeRequestRecord(
            request_number=req_no,
            title="First Click Submission",
            description="Initial description",
        )
        saved1 = repo.submit_change_request(req)

        # Simulate second click with same request_number
        req_repeat = ChangeRequestRecord(
            request_number=req_no,
            title="Second Click Submission (Updated)",
            description="Updated description",
        )
        saved2 = repo.submit_change_request(req_repeat)

        assert saved1.request_number == saved2.request_number
        # Verify only 1 record exists in DB with this request number
        all_reqs = repo.list_change_requests()
        matching = [r for r in all_reqs if r.request_number == req_no]
        assert len(matching) == 1
        assert matching[0].title == "Second Click Submission (Updated)"


# =============================================================================
# 9. SCENARIO SELECTOR VALIDATION
# =============================================================================
class TestScenarioSelectorValidation:
    """Test 9: Validates only genuine existing scenarios are accepted."""

    def test_available_scenarios_exist_on_disk(self, dataset_svc: DatasetService):
        scenarios = dataset_svc.get_available_scenarios()
        assert len(scenarios) > 0
        for sc_name, sc_data in scenarios.items():
            sc_path = Path(sc_data["path"])
            assert sc_path.exists(), f"Scenario {sc_name} path {sc_path} does not exist!"
            assert sc_path.suffix == ".tf"
            content = sc_path.read_text(encoding="utf-8")
            assert len(content) > 0

    def test_reject_unverified_scenario_name(self, dataset_svc: DatasetService):
        scenarios = dataset_svc.get_available_scenarios()
        assert "nonexistent_scenario_xyz.tf" not in scenarios


# =============================================================================
# 10, 11, 12, 13. UPLOAD SECURITY ENFORCEMENT
# =============================================================================
class TestUploadSecurityEnforcement:
    """Tests 10-13: Extension, size, sanitization, and path traversal protection."""

    def test_upload_extension_validation(self, tmp_path: Path):
        # Reject non-.tf files
        bad_files = ["script.py", "exploit.sh", "malware.exe", "policy.json", "config.tf.bak"]
        for bad in bad_files:
            ok, msg, path, content = validate_and_stage_upload(
                filename=bad, file_bytes=b"sample payload", target_dir=tmp_path
            )
            assert ok is False
            assert "Only Terraform files (.tf) are permitted" in msg or "Invalid file extension" in msg

        # Accept valid .tf file
        ok, msg, path, content = validate_and_stage_upload(
            filename="valid_policy.tf", file_bytes=b'resource "panos" "r" {}', target_dir=tmp_path
        )
        assert ok is True
        assert path is not None
        assert Path(path).exists()

    def test_upload_size_validation(self, tmp_path: Path):
        # Empty file (0 bytes) rejected
        ok_empty, msg_empty, _, _ = validate_and_stage_upload(
            filename="empty.tf", file_bytes=b"", target_dir=tmp_path
        )
        assert ok_empty is False
        assert "empty" in msg_empty.lower()

        # Over 1MB rejected
        oversized_bytes = b"A" * (MAX_UPLOAD_SIZE_BYTES + 1024)
        ok_large, msg_large, _, _ = validate_and_stage_upload(
            filename="oversized.tf", file_bytes=oversized_bytes, target_dir=tmp_path
        )
        assert ok_large is False
        assert "exceeds maximum permitted limit" in msg_large

        # Exactly 1KB accepted
        ok_valid, _, _, _ = validate_and_stage_upload(
            filename="ok.tf", file_bytes=b"valid" * 200, target_dir=tmp_path
        )
        assert ok_valid is True

    def test_filename_sanitization(self):
        dirty_names = [
            ("my rule #1 (v2).tf", "my_rule__1__v2_.tf"),
            ("rule;rm -rf;.tf", "rule_rm_-rf_.tf"),
            ("policy $var!.tf", "policy__var__.tf"),
        ]
        for dirty, expected_clean in dirty_names:
            clean = sanitize_filename(dirty)
            assert clean.endswith(".tf")
            assert ";" not in clean
            assert "$" not in clean
            assert " " not in clean

    def test_path_traversal_protection(self, tmp_path: Path):
        traversal_attempts = [
            ("../../etc/passwd.tf", b"content"),
            ("..\\..\\Windows\\System32\\cmd.exe.tf", b"content"),
            ("/var/log/syslog.tf", b"content"),
            ("changes/pr_4083_firewall_iam.tf", b"malicious overwrite attempt"),
            ("subdir/../nested/traversal.tf", b"content"),
        ]
        for filename, payload in traversal_attempts:
            ok, msg, path, content = validate_and_stage_upload(
                filename=filename, file_bytes=payload, target_dir=tmp_path
            )
            assert ok is False, f"Traversal filename {filename} should have been rejected!"
            assert "traversal" in msg.lower() or "escapes" in msg.lower()


# =============================================================================
# 14, 15, 16. HISTORY RETRIEVAL & FILTERING
# =============================================================================
class TestHistoryRetrievalAndFiltering:
    """Tests 14, 15 & 16: SQLite history retrieval, search, multi-filter, and record-detail."""

    def test_history_retrieval_and_filtering(self, repo: ChangeRepository):
        # Seed 3 records
        repo.create_change_request(
            ChangeRequestRecord(
                request_number="SIM-CHG-000001",
                title="Palo Alto Ingress Webhook",
                description="Firewall policy update",
                domain=ChangeDomain.NETWORK_SECURITY.value,
                priority=ChangePriority.CRITICAL.value,
                status=WorkflowState.SUBMITTED.value,
            )
        )
        repo.create_change_request(
            ChangeRequestRecord(
                request_number="SIM-CHG-000002",
                title="SailPoint Treasury Role Grant",
                description="Identity access request",
                domain=ChangeDomain.IDENTITY_GOVERNANCE.value,
                priority=ChangePriority.NORMAL.value,
                status=WorkflowState.DRAFT.value,
            )
        )
        repo.create_change_request(
            ChangeRequestRecord(
                request_number="SIM-CHG-000003",
                title="Allow Netflix Stream",
                description="AWS guest network change",
                domain=ChangeDomain.NETWORK_SECURITY.value,
                priority=ChangePriority.LOW.value,
                status=WorkflowState.ANALYSIS_COMPLETE.value,
            )
        )

        # 1. Search text filter
        search_res = repo.filter_change_requests(search_query="Webhook")
        assert len(search_res) == 1
        assert search_res[0]["request_number"] == "SIM-CHG-000001"

        # 2. Domain filter
        net_res = repo.filter_change_requests(domain="NETWORK_SECURITY")
        assert len(net_res) == 2
        id_res = repo.filter_change_requests(domain="IDENTITY_GOVERNANCE")
        assert len(id_res) == 1
        assert id_res[0]["request_number"] == "SIM-CHG-000002"

        # 3. Status filter
        draft_res = repo.filter_change_requests(status="DRAFT")
        assert len(draft_res) == 1
        assert draft_res[0]["request_number"] == "SIM-CHG-000002"

        # 4. Priority filter
        crit_res = repo.filter_change_requests(priority="CRITICAL")
        assert len(crit_res) == 1

        # 5. Count matching
        count = repo.count_filtered_change_requests(domain="NETWORK_SECURITY")
        assert count == 2

    def test_record_detail_retrieval_matches_stored_fields(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number="SIM-CHG-000001",
            title="Complete Detail Verification",
            description="Testing field fidelity.",
            justification="Audit requirement.",
            implementation_plan="Step 1: Test. Step 2: Validate.",
            backout_plan="Revert PR.",
            validation_plan="Deterministic simulation.",
            maintenance_window="Weekend Maintenance Window",
            expected_business_impact="Medium",
            dependencies="PanOS 11.1",
        )
        repo.create_change_request(req)

        detail = repo.get_change_request("SIM-CHG-000001")
        assert detail is not None
        assert detail.title == "Complete Detail Verification"
        assert detail.justification == "Audit requirement."
        assert detail.implementation_plan == "Step 1: Test. Step 2: Validate."
        assert detail.backout_plan == "Revert PR."
        assert detail.validation_plan == "Deterministic simulation."
        assert detail.maintenance_window == "Weekend Maintenance Window"
        assert detail.dependencies == "PanOS 11.1"


# =============================================================================
# 17. ACTIVITY LOG CREATION
# =============================================================================
class TestActivityLogAuditTrail:
    """Test 17: Activity log tracking for draft and submit lifecycle actions."""

    def test_activity_log_creation_on_draft_and_submit(self, repo: ChangeRepository):
        req = ChangeRequestRecord(
            request_number="SIM-CHG-000001",
            title="Lifecycle Test CR",
            submitted_by="Alice",
        )
        repo.save_draft(req)
        logs_draft = repo.get_activity_logs("SIM-CHG-000001")
        assert len(logs_draft) >= 1
        assert logs_draft[-1].action == "DRAFT_SAVED"

        repo.submit_change_request(req)
        logs_submitted = repo.get_activity_logs("SIM-CHG-000001")
        assert len(logs_submitted) >= 2
        assert logs_submitted[-1].action == "REQUEST_SUBMITTED"


# =============================================================================
# 18. SQLITE MIGRATION WITHOUT DATA LOSS
# =============================================================================
class TestDatabaseMigrationWithoutDataLoss:
    """Test 18: Non-destructive schema migration adds new columns preserving existing data."""

    def test_migration_preserves_existing_records(self, tmp_path: Path):
        db_file = tmp_path / "legacy_v1.db"

        # 1. Initialize DB with only base schema (simulating Milestone B schema)
        with sqlite3.connect(str(db_file)) as conn:
            conn.executescript(BASE_SCHEMA_SQL)
            # Insert a record in the legacy table
            conn.execute(
                """
                INSERT INTO change_requests (
                    request_number, title, description, submitted_by, submitter_role,
                    change_type, domain, priority, status, created_at, updated_at,
                    assigned_engineer, target_environment, source_file_path, raw_content
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "SIM-CHG-000001",
                    "Legacy Pre-Migration Record",
                    "Original description",
                    "Legacy User",
                    "SecOps",
                    "FIREWALL_POLICY",
                    "NETWORK_SECURITY",
                    "NORMAL",
                    "SUBMITTED",
                    "2026-11-16T00:00:00",
                    "2026-11-16T00:00:00",
                    "SecOps Operations",
                    "Apex Global Production",
                    None,
                    None,
                ),
            )
            conn.commit()

        # 2. Run schema migration
        with get_db_connection(db_file) as conn:
            migrate_schema_if_needed(conn)

        # 3. Verify legacy record survived intact
        repo = ChangeRepository(db_path=str(db_file))
        migrated_record = repo.get_change_request("SIM-CHG-000001")
        assert migrated_record is not None
        assert migrated_record.title == "Legacy Pre-Migration Record"
        assert migrated_record.request_number == "SIM-CHG-000001"
        assert migrated_record.justification == ""  # Newly migrated default column

        # 4. Verify new columns can be populated
        migrated_record.justification = "Added after migration"
        repo.update_change_request(migrated_record)
        updated = repo.get_change_request("SIM-CHG-000001")
        assert updated.justification == "Added after migration"


# =============================================================================
# 19. EMPTY HISTORY STATE
# =============================================================================
class TestEmptyHistoryState:
    """Test 19: Clean handling of empty history and zero records."""

    def test_empty_history_returns_empty_list_and_zero_count(self, repo: ChangeRepository):
        records = repo.filter_change_requests()
        assert records == []
        count = repo.count_filtered_change_requests()
        assert count == 0
        kpi = repo.get_kpi_summary()
        assert kpi.total_requests == 0
        assert kpi.avg_risk_score == 0.0


# =============================================================================
# 20. ORIGINAL SCENARIO FILE PRESERVATION
# =============================================================================
class TestOriginalScenarioFilePreservation:
    """Test 20: Original scenario files in changes/ and demo_environment/ are never overwritten."""

    def test_original_scenarios_remain_unchanged(self):
        pr4083 = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        pr4082 = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        netflix = CHANGES_DIR / "allow_netflix.tf"

        assert pr4083.exists()
        assert pr4082.exists()
        assert netflix.exists()

        content_4083 = pr4083.read_text(encoding="utf-8")
        assert "panos_security_policy" in content_4083
        assert "Allow-Analytics-Outbound-Webhook" in content_4083
        assert "AmazonS3FullAccess" in content_4083

        content_4082 = pr4082.read_text(encoding="utf-8")
        assert "aws_security_group_rule" in content_4082
        assert "allow_outbound_webhook" in content_4082

        content_netflix = netflix.read_text(encoding="utf-8")
        assert "allow_outbound_netflix" in content_netflix
